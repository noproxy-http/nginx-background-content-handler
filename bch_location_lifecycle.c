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
 * File:   bch_location_lifecycle.c
 * Author: alex
 *
 * Created on March 13, 2021, 12:25 PM
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "bch_location_lifecycle.h"

#include "bch_data.h"
#include "bch_dlopen.h"
#include "bch_functions.h"
#include "bch_http_notify_callback.h"

#ifndef _WIN32
#include "bch_selfpipe_notify_callback.h"
#endif //!_WIN32

typedef int (*bch_initialize_type)(
        bch_send_response_type response_callback,
        const char* hanler_config,
        int hanler_config_len);

static char* unescape_spaces(ngx_str_t str) {
    char* res = malloc(str.len + 1);
    if (NULL == res) {
        return NULL;
    }
    memset(res, '\0', str.len + 1);
    size_t j = 0;
    for (size_t i = 0; i < str.len; i++) {
        char ch = str.data[i];
        if (!('\\' == ch && i < str.len - 1 && ' ' == str.data[i + 1])) {
            res[j] = ch;
            j++;
        }
    }
    return res;
}

ngx_int_t bch_location_init(ngx_log_t* log, bch_loc_ctx* ctx) {
    // load handler shared lib
    if (0 == ctx->libname.len) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "bch_location_lifecycle: handler shared library not specified");
        return NGX_ERROR;
    }

    char* libname_noesc = unescape_spaces(ctx->libname);
    if (NULL == libname_noesc) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "bch_location_lifecycle: alloc failed, size [%d]", ctx->libname.len);
        return NGX_ERROR;
    }

    // load lib, conf values are NUL-terminated
    void* lib = bch_dyload_library(log, libname_noesc);
    free(libname_noesc);
    if (NULL == lib) {
        return NGX_ERROR;
    }

    // lookup init
    bch_initialize_type init_fun = (bch_initialize_type) bch_dyload_symbol(log, lib, "bch_initialize");
    if (NULL == init_fun) {
        return NGX_ERROR;
    }

    // lookup receive and free
    ctx->receive_request_fun = (bch_receive_request_type) bch_dyload_symbol(log, lib, "bch_receive_request");
    if (NULL == ctx->receive_request_fun) {
        return NGX_ERROR;
    }
    ctx->free_response_data_fun = (bch_free_response_data_type) bch_dyload_symbol(log, lib, "bch_free_response_data");
    if (NULL == ctx->free_response_data_fun) {
        return NGX_ERROR;
    }

    char* appconf_noesc = unescape_spaces(ctx->appconf);
    if (NULL == appconf_noesc) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "bch_location_lifecycle: alloc failed, size [%d]", ctx->appconf.len);
        return NGX_ERROR;
    }

    bch_send_response_type notify_cb = bch_http_notify_callback;
#ifndef _WIN32
    if (0 == ctx->notify_port) {
        notify_cb = bch_selfpipe_notify_callback;
    }
#endif //!_WIN32

    // call init
    int err_init = init_fun(notify_cb, appconf_noesc, strlen(appconf_noesc));
    free(appconf_noesc);
    if (0 != err_init) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "bch_location_lifecycle application init error, code [%d]", err_init);
        return NGX_ERROR;
    }

    return NGX_OK;
}

void bch_location_shutdown(ngx_log_t* log, bch_loc_ctx* ctx) {
    // todo
    ngx_log_error(NGX_LOG_ERR, log, 0,
            "bch_location_lifecycle: shutdown called, libname [%s]", ctx->libname.data);
}
