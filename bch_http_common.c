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
 * File:   bch_http_common.c
 * Author: alex
 *
 * Created on February 2, 2021, 10:28 PM
 */

#include "bch_http_common.h"

ngx_int_t bch_send_buffer(ngx_http_request_t* r, ngx_buf_t* buf) {
    // send headers
    ngx_int_t err_headers = ngx_http_send_header(r);
    if (NGX_OK != err_headers) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error sending headers");
        ngx_http_finalize_request(r, NGX_ERROR);
        return err_headers;
    }

    // send data
    ngx_chain_t chain;
    chain.buf = buf;
    chain.next = NULL;
    ngx_int_t err_filters = ngx_http_output_filter(r, &chain);
    if (NGX_OK != err_filters) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error sending data");
        ngx_http_finalize_request(r, NGX_ERROR);
        return err_filters;
    }

    // release request
    ngx_http_finalize_request(r, NGX_HTTP_OK);

    return NGX_OK;
}