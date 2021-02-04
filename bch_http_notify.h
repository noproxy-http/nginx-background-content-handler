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
 * File:   bch_http_notify.h
 * Author: alex
 *
 * Created on January 31, 2021, 11:55 AM
 */

#ifndef BCH_HTTP_NOTIFY_H
#define BCH_HTTP_NOTIFY_H

#include "jansson.h"

typedef struct bch_resp {
    void* r;
    unsigned int status;
    json_t* headers;
    u_char* data;
    size_t data_len;
} bch_resp;

int bch_http_notify_init(int tcp_port);

int bch_http_notify_callback(void* request, int http_status,
        const char* headers, int headers_len,
        const char* data, int data_len);

#endif /* BCH_HTTP_NOTIFY_H */

