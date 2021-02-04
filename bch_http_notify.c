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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

static uint16_t notify_tcp_port = 0;
static int notify_sock = -1;
static const char* notify_req_template = "GET /?%lld HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n";

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
    if (http_status < 200 || http_status > 599) {
        return NULL;
    }

    if (data_len < 0) {
        return NULL;
    } 
    u_char* data_cp = NULL;
    if (data_len > 0 && NULL != data) {
        data_cp = malloc(data_len);
        if (NULL == data_cp) {
            return NULL;
        }
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

    resp->r = request;
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
    while (!http_resp_received(buf, len)) {
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

    char* endptr;
    long status = strtol(status_buf, &endptr, 0);
    if (status_buf + 3 != endptr) {
        return -1;
    }

    return (int) status;
}

int bch_http_notify_init(int tcp_port) {
    notify_tcp_port = (uint16_t) tcp_port;
    return 0;
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
