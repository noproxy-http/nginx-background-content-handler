/*
 * Copyright 2021, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * File:   bch_http_notify.c
 * Author: alex
 *
 * Created on January 31, 2021, 11:55 AM
 */

#include "bch_http_notify.h"

#include <stdio.h>

#include <stdint.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <unistd.h>

#include "jansson.h"

#include "bch_http_common.h"


static uint16_t notify_tcp_port = 0;
static int notify_sock = -1;
static const char* notify_req_template = "GET /?%lld HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n";

typedef struct bch_resp {
    ngx_http_request_t* r;
    ngx_int_t status;
    json_t* headers;
    u_char* data;
    size_t data_len;
} bch_resp;


static json_t* parse_headers(const char* headers, int headers_len) {
    // parse
    size_t ulen = headers_len;
    json_t* root = json_loadb(headers, ulen, JSON_REJECT_DUPLICATES, NULL);
    if (NULL == root) {
        return NULL;
    }

    // validate
    if (!json_is_object(root)) {
        json_decref(root);
        return NULL;
    }
    const char *key;
    json_t *value;
    json_object_foreach(root, key, value) {
        if (0 == strlen(key) || !json_is_string(value)) {
            json_decref(root);
            return NULL;
        }
    }

    return root;
}

static bch_resp* create_resp(void* request, int http_status,
        const char* headers, int headers_len,
        const char* data, int data_len) {
    if (NULL == request) {
        return NULL;
    }
    if (http_status < 200 || http_status > 511) {
        return NULL;
    }

    if (data_len < 0) {
        return NULL;
    } 
    u_char* data_cp = NULL;
    if (data_len > 0 && NULL != data) {
        data_cp = malloc(data_len);
        memcpy(data_cp, data, data_len);
    }

    json_t* headers_json = parse_headers(headers, headers_len);
    if (NULL == headers_json) {
        free(data_cp);
        return NULL;
    }
    bch_resp* resp = malloc(sizeof(bch_resp));
    if (NULL == resp) {
        free(data_cp);
        json_decref(headers_json);
        return NULL;
    }

    resp->r = (ngx_http_request_t*) request;
    resp->status = http_status;
    resp->headers = headers_json;
    resp->data = data_cp;
    resp->data_len = (size_t) data_len;

    return resp;
}

static int open_socket(uint16_t port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return sock;
    }

    struct sockaddr_in addr;
    memset(&addr, '\0', sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int err_conn = connect(sock, (struct sockaddr*) &addr, sizeof(addr));
    if (err_conn < 0) {
        return err_conn;
    }

    return sock;
}

static int notification_received(char* buf, size_t len) {
    if (len > 4) {
        return  '\r' == buf[len - 4] &&
                '\n' == buf[len - 3] &&
                '\r' == buf[len - 2] &&
                '\n' == buf[len - 1];
    } else {
        return 0;
    }
}

static int write_to_socket(bch_resp* resp, int sock, uint16_t port) {
    // prepare req
    uint64_t ptr = (uint64_t) resp;
    char notify_req[128];
    int req_len = snprintf(notify_req, sizeof(notify_req), notify_req_template, ptr, port);
    if (req_len >= (int) sizeof(notify_req)) {
        return -1;
    }

    // write
    size_t to_send = req_len;
    size_t idx = 0;
    while (idx < to_send) {
        int written = write(sock, notify_req + idx, to_send - idx);
        if (-1 == written) {
            return -1;
        }
        idx += written;
    }

    // read
    char buf[512];
    size_t len = 0;
    while (!notification_received(buf, len)) {
        int rread = read(sock, buf + len, sizeof(buf) - len);
        if (-1 == rread) {
            return -1;
        }
        len += rread;
    }

    // parse status
    // HTTP/1.1 200
    // 0123456789012
    if (len < 12) {
        return -1;
    }
    char status_buf[4];
    memset(&status_buf, '\0', sizeof(status_buf));
    memcpy(status_buf, buf + 9, 3);

    fprintf(stderr, "status: [%s]\n", status_buf);
    
    char* endptr;
    long status = strtol(status_buf, &endptr, 0);
    if (status_buf + 3 != endptr) {
        return -1;
    }

    return (int) status;
}

static bch_resp* get_resp(ngx_log_t* log, ngx_str_t args) {
    if (0 == args.len) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "'bch_http_notify': no response specified on notify call");
        return NULL;
    }
    if (args.len >= 32) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "'bch_http_notify': invalid response handle, length: [%l]", args.len);
        return NULL;
    }
    char cstr[32];
    memset(cstr, '\0', sizeof(cstr));
    memcpy(cstr, (const char*) args.data, args.len);
    char* endptr;
    errno = 0;
    long long handle = strtoll(cstr, &endptr, 0);
    if (errno == ERANGE || cstr + args.len != endptr) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "'bch_http_notify': cannot parse handle from string, value: [%s]", cstr);
        return NULL;
    }
    return (bch_resp*) handle;
}

static ngx_int_t add_header(ngx_http_request_t* r, const char* key_in, const char* value_in) {

    // copy key
    ngx_str_t key;
    key.len = strlen(key_in);
    key.data = ngx_pcalloc(r->pool, key.len);
    if (NULL == key.data) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': pool allocation error, size: [%l]", key.len);
        return NGX_ERROR;
    }
    memcpy(key.data, key_in, key.len);

    // copy value
    ngx_str_t value;
    value.len = strlen(value_in);
    value.data = ngx_pcalloc(r->pool, value.len);
    if (NULL == value.data) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': pool allocation error, size: [%l]", value.len);
        return NGX_ERROR;
    }
    memcpy(value.data, value_in, value.len);

    // set header
    ngx_table_elt_t* hout = ngx_list_push(&r->headers_out.headers);
    if (hout == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': header allocation error");
        return NGX_ERROR;
    }
    hout->key = key;
    hout->value = value;
    hout->hash = 1;

    return NGX_OK;
}

static ngx_buf_t* create_client_resp_buf(bch_resp* resp) {

    ngx_buf_t* buf = ngx_pcalloc(resp->r->pool, sizeof(ngx_buf_t));
    if (NULL == buf) {
        ngx_log_error(NGX_LOG_ERR, resp->r->connection->log, 0,
                "'bch_http_notify': pool allocation error, size: [%l]", sizeof(ngx_buf_t));
        return NULL;
    }

    if (resp->data_len > 0) {
        buf->pos = ngx_pcalloc(resp->r->pool, resp->data_len);
        if (NULL == buf->pos) {
            ngx_log_error(NGX_LOG_ERR, resp->r->connection->log, 0,
                    "'bch_http_notify': error allocating buffer, size: [%l]", resp->data_len);
            return NULL;
        }
        memcpy(buf->pos, resp->data, resp->data_len);
        buf->last = buf->pos + resp->data_len;
        buf->start = buf->pos;
        buf->end = buf->last;
        buf->memory = 1;
        buf->last_buf = 1;
    } else {
        buf->pos = 0;
        buf->last = 0;
        buf->last_buf = 1;
    }

    return buf;

}

static ngx_int_t send_client_resp(bch_resp* resp) {

    ngx_http_request_t* r = resp->r;

    if (r->connection->error) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': request already finalized, counter: [%d]", r->count);
        ngx_http_finalize_request(r, NGX_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "'bch_http_notify' 1, counter: [%d]", resp->r->count);

    // headers
    const char *key;
    json_t *value;
    json_object_foreach(resp->headers, key, value) {
        const char* val = json_string_value(value);
        ngx_int_t err_set = add_header(r, key, val);
        if (NGX_OK != err_set) {
            ngx_http_finalize_request(r, NGX_ERROR);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    
    // todo: file
    // data
    ngx_buf_t* buf = create_client_resp_buf(resp);
    if (NULL == buf) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // send
    r->headers_out.status = resp->status;
    r->headers_out.content_length_n = resp->data_len;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "'bch_http_notify' 3, status: [%d]", resp->status);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "'bch_http_notify' 4, len: [%d]", resp->data_len);

    ngx_int_t err_send = bch_send_buffer(r, buf);
    if (NGX_OK == err_send) {
        ngx_http_run_posted_requests(r->connection);
        return NGX_HTTP_OK;
    } else {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}

ngx_int_t bch_http_notify_init(ngx_log_t* log, uint16_t tcp_port) {
    (void) log;
    notify_tcp_port = tcp_port;
    return NGX_OK;
}

int bch_http_notify_callback(void* request, int http_status,
        const char* headers, int headers_len,
        const char* data, int data_len) {

    // open socket on first call or after error
    if (notify_sock < 0) {
        if (0 == notify_tcp_port) {
            return -1;
        }
        int sock = open_socket(notify_tcp_port);
        if (sock < 0) {
            return -1;
        }
        notify_sock = sock;
    }

    // copy resp
    bch_resp* resp = create_resp(request, http_status, headers, headers_len, data, data_len);
    if (NULL == resp) {
        return -1;
    }

    // write to socket
    int status = write_to_socket(resp, notify_sock, notify_tcp_port);
    if (200 != status) {
        close(notify_sock);
        notify_sock = -1;
        free(resp->data);
        json_decref(resp->headers);
        free(resp);
    }
    return status;
}

ngx_int_t bch_http_notify_handler(ngx_http_request_t *r) {

    ngx_int_t status = 0;

    // get client response
    bch_resp* resp = get_resp(r->connection->log, r->args);
    if (NULL == resp) {
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    } else {
        status = send_client_resp(resp);
        free(resp->data);
        json_decref(resp->headers);
        free(resp);
    }

    // own response
    ngx_buf_t* buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (NULL == buf) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': pool allocation error, size: [%l]", sizeof(ngx_buf_t));
        ngx_http_finalize_request(r, NGX_ERROR);
        return NGX_ERROR;
    }
    buf->pos = 0;
    buf->last = 0;
    buf->last_buf = 1;

    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;

    r->main->count++;
    return bch_send_buffer(r, buf);
}

