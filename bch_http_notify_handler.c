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

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#else //_WIN32
#include <windows.h>
#define close CloseHandle
#endif // !_WIN32

#include "jansson.h"

#include "bch_data.h"
#include "bch_notify_handler.h"

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

ngx_int_t bch_http_notify_handler(ngx_http_request_t *r) {
    ngx_int_t status = 0;

    // client response
    bch_resp* resp = get_resp(r->connection->log, r->args);
    if (NULL == resp) {
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    } else {
        status = bch_send_resp_to_client(resp);
        if (NGX_HTTP_OK == status || NGX_HTTP_BAD_GATEWAY == status) {
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
    return bch_send_buffer(r, buf);
}
