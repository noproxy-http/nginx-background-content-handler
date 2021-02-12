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
 * File:   bch_http_notify_callback.c
 * Author: alex
 *
 * Created on February 5, 2021, 12:22 PM
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "bch_http_notify_callback.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#else // !_WIN32
#include <winsock2.h>
#define close closesocket
#endif // _WIN32

#include "bch_data.h"

static const char* notify_req_template = "GET /?%lld HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n";

#ifdef _WIN32
#pragma warning( disable: 4706 )
#endif // _WIN32
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
#ifdef _WIN32
#pragma warning( default: 4706 )
#endif // _WIN32
}

static bch_resp* create_resp(void* request, int http_status,
        const char* headers, int headers_len,
        char* data, int data_len) {
    if (NULL == request) {
        return NULL;
    }
    if (http_status < 200 || http_status > 599) {
        return NULL;
    }

    if (data_len < 0) {
        return NULL;
    } 

    json_t* headers_json = parse_headers(headers, headers_len);
    if (NULL == headers_json) {
        return NULL;
    }
    bch_resp* resp = malloc(sizeof(bch_resp));
    if (NULL == resp) {
        json_decref(headers_json);
        return NULL;
    }

    resp->request = request;
    resp->status = http_status;
    resp->headers = headers_json;
    resp->data = (u_char*) data;
    resp->data_len = (size_t) data_len;

    return resp;
}

static int open_socket(uint16_t port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return sock;
    }

    struct linger sl;
    sl.l_onoff = 1;     /* non-zero value enables linger option in kernel */
    sl.l_linger = 0;    /* timeout interval in seconds */
    int err_linger = setsockopt(sock, SOL_SOCKET, SO_LINGER, (char*) &sl, sizeof(sl));
    if (0 != err_linger) {
        return err_linger;
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

static int http_resp_received(char* buf, size_t len) {
    if (len > 4) {
        return  '\r' == buf[len - 4] &&
                '\n' == buf[len - 3] &&
                '\r' == buf[len - 2] &&
                '\n' == buf[len - 1];
    } else {
        return 0;
    }
}

static int write_to_socket(bch_resp* resp, int retry);

static int close_and_retry(bch_resp* resp) {
    bch_loc_ctx* ctx = resp->request->ctx;
    close(ctx->notify_sock);
    ctx->notify_sock = 0;
    return write_to_socket(resp, 0);
}

static int write_to_socket(bch_resp* resp, int retry) {
    bch_loc_ctx* ctx = resp->request->ctx;
    if (0 == ctx->notify_sock) {
        int sock = open_socket(ctx->notify_port);
        if (sock < 0) {
            return -2;
        }
        ctx->notify_sock = sock;
    }
    
    // prepare req
    uint64_t ptr = (uint64_t) resp;
    char notify_req[128];
    int req_len = snprintf(notify_req, sizeof(notify_req), notify_req_template, ptr, ctx->notify_port);
    if (req_len >= (int) sizeof(notify_req)) {
        return -3;
    }

    // write
    size_t to_send = req_len;
    size_t idx = 0;
    while (idx < to_send) {
        int written = send(ctx->notify_sock, notify_req + idx, to_send - idx, 0);
        if (-1 == written) {
            if (retry > 0) {
                return close_and_retry(resp);
            } else {
                return -4;
            }
        }
        idx += written;
    }

    // read
    char buf[512];
    size_t len = 0;
    do {
        int rread = recv(ctx->notify_sock, buf + len, sizeof(buf) - len, 0);
        if (-1 == rread || 0 == rread) {
            if (retry > 0) {
                return close_and_retry(resp);
            } else {
                return -5;
            }
        }
        len += rread;
    } while (!http_resp_received(buf, len));

    // parse status
    // HTTP/1.1 200
    // 0123456789012
    if (len < 12) {
        return -6;
    }
    char status_buf[4];
    memset(&status_buf, '\0', sizeof(status_buf));
    memcpy(status_buf, buf + 9, 3);

    char* endptr;
    long status = strtol(status_buf, &endptr, 0);
    if (status_buf + 3 != endptr) {
        return -7;
    }

    return (int) status;
}

int bch_http_notify_callback(void* request, int http_status,
        const char* headers, int headers_len,
        char* data, int data_len) {

    // copy resp
    bch_resp* resp = create_resp(request, http_status, headers, headers_len, data, data_len);
    if (NULL == resp) {
        return -1;
    }
    bch_loc_ctx* ctx = resp->request->ctx;

    // write to socket
    int status = write_to_socket(resp, 1);
    if (200 != status) {
        close(ctx->notify_sock);
        ctx->notify_sock = 0;
        if (502 != status) {
            if (NULL != data) {
                ctx->free_response_data_fun(data);
            }
            json_decref(resp->headers);
            free(resp);
        }
    }

    // return code
    if (200 == status) {
        return 0;
    } else if (status < 0) {
        return status;
    } else if (502 == status) {
        return 1;
    } else if (500 == status) {
        return 2;
    } else {
        return 3;
    }
}
