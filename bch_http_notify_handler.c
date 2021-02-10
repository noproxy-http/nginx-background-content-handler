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
 * File:   bch_http_notify_handler.c
 * Author: alex
 *
 * Created on February 4, 2021, 6:26 PM
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "bch_http_notify_handler.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "jansson.h"

#include "bch_data.h"

static const char BCH_HEADER_PREFIX[] = "X-Background-Content-Handler";
static const char BCH_HEADER_DATA_FILE[] = "X-Background-Content-Handler-Data-File";

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

static ngx_int_t add_single_header(ngx_http_request_t* r, const char* key_in, const char* value_in) {
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

#ifdef _WIN32
#pragma warning( disable: 4706 )
#endif // _WIN32
static ngx_int_t add_headers(bch_resp* resp, const char** data_file_out) {
    ngx_http_request_t* r = resp->request->r;
    const char *key;
    json_t *value;
    json_object_foreach(resp->headers, key, value) {
        const char* val = json_string_value(value);
        size_t key_len = strlen(key);
        size_t pref_len = sizeof(BCH_HEADER_PREFIX) - 1;
        if (key_len < pref_len || 0 != strncmp(BCH_HEADER_PREFIX, key, pref_len)) {
            ngx_int_t err_set = add_single_header(r, key, val);
            if (NGX_OK != err_set) {
                return err_set;
            }
        } else { // internal header
            size_t hdf_len = sizeof(BCH_HEADER_DATA_FILE) - 1;
            if (key_len == hdf_len && 0 == strncmp(BCH_HEADER_DATA_FILE, key, hdf_len)) {
                *data_file_out = val;
            } else {
                // ignore
            }
        }
    }
    return NGX_OK;
#ifdef _WIN32
#pragma warning( default: 4706 )
#endif // _WIN32
}

static ngx_temp_file_t* create_temp_file(ngx_http_request_t* r, const char* data_file, size_t* data_file_len) {
    // open file
    struct stat st;
    int err_stat = stat(data_file, &st);
    if (0 != err_stat) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': cannot stat response file, path: [%s]", data_file);
        return NULL;
    }
    ngx_fd_t fd = open(data_file, O_RDONLY);
    if (-1 == fd) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': cannot open response file, path: [%s]", data_file);
        return NULL;
    }

    // temp file
    ngx_temp_file_t* tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
    if (tf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': error allocating buffer, size: [%l]", sizeof(ngx_temp_file_t));
        return NULL;
    }
    tf->file.fd = fd;
    tf->file.log = r->connection->log;
    tf->pool = r->pool;
    tf->clean = 1;

    // cleanup
    u_char* name_cleanup = ngx_pcalloc(r->pool, strlen(data_file) + 1);
    if (NULL == name_cleanup) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': error allocating buffer, size: [%d]", strlen(data_file) + 1);
        return NULL;
    }
    memcpy(name_cleanup, data_file, strlen(data_file));
    ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': error creating reponse file cleanup struct]");
        return NULL;
    }
    cln->handler = ngx_pool_delete_file;
    ngx_pool_cleanup_file_t* clnf = cln->data;
    clnf->fd = fd;
    clnf->name = name_cleanup;
    clnf->log = r->connection->log;

    // content size
    *data_file_len = st.st_size;

    return tf;
}

static ngx_buf_t* create_client_buf(bch_resp* resp, const char* data_file, size_t* data_file_len) {
    ngx_http_request_t* r = resp->request->r;

    ngx_buf_t* buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (NULL == buf) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': pool allocation error, size: [%l]", sizeof(ngx_buf_t));
        return NULL;
    }

    if (NULL == data_file) {
        if (resp->data_len > 0) {
            buf->pos = ngx_pcalloc(r->pool, resp->data_len);
            if (NULL == buf->pos) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "'bch_http_notify': error allocating buffer, size: [%l]", resp->data_len);
                return NULL;
            }
            memcpy(buf->pos, resp->data, resp->data_len);
            buf->last = buf->pos + resp->data_len;
            buf->start = buf->pos;
            buf->end = buf->last;
            buf->memory = 1;
        } else {
            buf->pos = 0;
            buf->last = 0;
        }
    } else { // temp file
        ngx_temp_file_t* fi = create_temp_file(r, data_file, data_file_len);
        if (NULL == fi) {
            return NULL;
        }
        buf->file = (ngx_file_t*) fi;
        buf->file_pos = 0;
        buf->file_last = *data_file_len;
        buf->in_file = 1;
        buf->temp_file = 1;
    }

    buf->last_buf = 1;
    return buf;
}

static ngx_int_t send_buffer(ngx_http_request_t* r, ngx_buf_t* buf) {
    // send headers
    ngx_int_t err_headers = ngx_http_send_header(r);
    if (NGX_OK != err_headers) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': error sending headers, code: [%d]", err_headers);
        ngx_http_finalize_request(r, NGX_ERROR);
        return err_headers;
    }

    // send data
    ngx_chain_t chain;
    chain.buf = buf;
    chain.next = NULL;
    ngx_int_t err_filters = ngx_http_output_filter(r, &chain);
    if (NGX_OK != err_filters && NGX_AGAIN != err_filters) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': error sending data, code: [%d]", err_filters);
        ngx_http_finalize_request(r, NGX_ERROR);
        return err_filters;
    }

    return NGX_OK;
}

static ngx_int_t send_client_resp(bch_resp* resp) {
    ngx_http_request_t* r = resp->request->r;

    if (r->connection->error) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': request already finalized, counter: [%d]", r->count);
        ngx_http_finalize_request(r, NGX_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // headers
    const char* data_file = NULL;
    ngx_int_t err_headers = add_headers(resp, &data_file);
    if (NGX_OK != err_headers) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // data
    size_t data_file_len = 0;
    ngx_buf_t* buf = create_client_buf(resp, data_file, &data_file_len);
    if (NULL == buf) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // send
    r->headers_out.status = resp->status;
    if (NULL == data_file) {
        r->headers_out.content_length_n = resp->data_len;
    } else {
        r->headers_out.content_length_n = data_file_len;
    }

    ngx_int_t err_send = send_buffer(r, buf);
    if (NGX_OK == err_send) {
        ngx_http_finalize_request(r, NGX_HTTP_OK);
        ngx_http_run_posted_requests(r->connection);
        return NGX_HTTP_OK;
    } else {
        ngx_http_finalize_request(r, NGX_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}

ngx_int_t bch_http_notify_handler(ngx_http_request_t *r) {
    ngx_int_t status = 0;

    // client response
    bch_resp* resp = get_resp(r->connection->log, r->args);
    if (NULL == resp) {
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    } else {
        status = send_client_resp(resp);
        if (200 == status) {
            free(resp->data);
            json_decref(resp->headers);
            free(resp);
        }
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
    return send_buffer(r, buf);
}
