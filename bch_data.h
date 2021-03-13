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
 * File:   bch_data.h
 * Author: alex
 *
 * Created on February 5, 2021, 12:12 PM
 */

#ifndef BCH_DATA_H
#define BCH_DATA_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdint.h>

#include "jansson.h"

extern ngx_module_t ngx_http_background_content_handler_module;

#ifndef _WIN32
extern int bch_selfpipe_fd_in;
extern int bch_selfpipe_fd_out;
#endif //!_WIN32

typedef int (*bch_receive_request_type)(
        void* request,
        const char* metadata, int metadata_len,
        const char* data, int data_len);

typedef void (*bch_free_response_data_type)(
        void* data);

typedef void (*bch_shutdown_type)();

typedef struct bch_loc_ctx {
    ngx_str_t libname;
    ngx_str_t appconf;

    bch_receive_request_type receive_request_fun;
    bch_free_response_data_type free_response_data_fun;
    bch_shutdown_type shutdown_fun;

    uint16_t notify_port;
    int notify_sock;
} bch_loc_ctx;

typedef struct bch_req {
    ngx_http_request_t* r;
    bch_loc_ctx* ctx;
} bch_req;

typedef struct bch_resp {
    bch_req* request;
    uint16_t status;
    json_t* headers;
    u_char* data;
    size_t data_len;
} bch_resp;

typedef struct bch_main_ctx {
    bch_loc_ctx** locations;
    size_t locations_count;
} bch_main_ctx;

#endif /* BCH_DATA_H */

