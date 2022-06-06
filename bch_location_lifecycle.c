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

static ngx_int_t dyload_deps(ngx_log_t* log, bch_loc_ctx* ctx, void*** deplibs_out) {
    void** libs = malloc(sizeof(void*) * ctx->deplibs->nelts);
    if (NULL == libs) {
        return NGX_ERROR;
    }
    
    ngx_str_t* elts = ctx->deplibs->elts;
    for (size_t i = 0; i < ctx->deplibs->nelts; i++) {
        char* libname_noesc = bch_unescape_spaces(log, elts[i]);
        if (NULL == libname_noesc) {
            free(libs);
            return NGX_ERROR;
        }

        // load lib, conf values are NUL-terminated
        void* lib = bch_dyload_library(log, libname_noesc);
        free(libname_noesc);
        if (NULL == lib) {
            free(libs);
            return NGX_ERROR;
        }
        libs[i] = lib;
    }

    if (NULL != deplibs_out) {
        *deplibs_out = libs;
    } else {
        free(libs);
    }
    return NGX_OK;
}

static ngx_int_t close_deps(ngx_log_t* log, bch_loc_ctx* ctx, void** deplibs) {
    for (size_t i = 0; i < ctx->deplibs->nelts; i++) {
        int err_close = bch_dyload_close(log, deplibs[i]);
        if (0 != err_close) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

static void* dyload_handler_lib(ngx_log_t* log, bch_loc_ctx* ctx) {
    if (0 == ctx->libname.len) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "bch_location_check_dyload: handler shared library not specified");
        return NULL;
    }

    char* libname_noesc = bch_unescape_spaces(log, ctx->libname);
    if (NULL == libname_noesc) {
        return NULL;
    }

    // load lib, conf values are NUL-terminated
    void* lib = bch_dyload_library(log, libname_noesc);
    free(libname_noesc);
    return lib;
}

char* bch_unescape_spaces(ngx_log_t* log, ngx_str_t str) {
    char* res = malloc(str.len + 1);
    if (NULL == res) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "bch_unescape_spaces: alloc failed, size [%d]", str.len);
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

ngx_int_t bch_location_check_dyload(ngx_log_t* log, bch_loc_ctx* ctx) {
    // load handler lib dependencies, if any
    void** deplibs = NULL;
    ngx_int_t err_deps = dyload_deps(log, ctx, &deplibs);
    if (NGX_OK != err_deps) {
        return err_deps;
    }

    // check lib can be loaded, symbols checks are omitted
    void* lib = dyload_handler_lib(log, ctx);
    if (NULL == lib) {
        free(deplibs);
        return NGX_ERROR;
    }

#ifndef _WIN32
    // FreeLibrary at this point causes Access Violation
    int err_closed = bch_dyload_close(log, lib);
    if (0 != err_closed) {
        free(deplibs);
        return NGX_ERROR;
    }
    int err_deps_closed = close_deps(log, ctx, deplibs);
    free(deplibs);
    if (0!= err_deps_closed) {
        return NGX_ERROR;
    }
#else //!_WIN32
    (void) close_deps;
    free(deplibs);
#endif //!_WIN32

    return NGX_OK;
}

ngx_int_t bch_location_init(ngx_log_t* log, bch_loc_ctx* ctx) {
    // load handler lib dependencies, if any
    ngx_int_t err_deps = dyload_deps(log, ctx, NULL);
    if (NGX_OK != err_deps) {
        return NGX_ERROR;
    }

    // load handler shared lib
    void* lib = dyload_handler_lib(log, ctx);
    if (NULL == lib) {
        return NGX_ERROR;
    }

    // lookup init
    bch_initialize_type init_fun = (bch_initialize_type) bch_dyload_symbol(log, lib, "bch_initialize");
    if (NULL == init_fun) {
        return NGX_ERROR;
    }

    // lookup receive, free and shutdown
    ctx->receive_request_fun = (bch_receive_request_type) bch_dyload_symbol(log, lib, "bch_receive_request");
    if (NULL == ctx->receive_request_fun) {
        return NGX_ERROR;
    }
    ctx->free_response_data_fun = (bch_free_response_data_type) bch_dyload_symbol(log, lib, "bch_free_response_data");
    if (NULL == ctx->free_response_data_fun) {
        return NGX_ERROR;
    }
    ctx->shutdown_fun = (bch_shutdown_type) bch_dyload_symbol(log, lib, "bch_shutdown");
    if (NULL == ctx->shutdown_fun) {
        return NGX_ERROR;
    }

    char* appconf_noesc = bch_unescape_spaces(log, ctx->appconf);
    if (NULL == appconf_noesc) {
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
                "bch_location_init: application init error, code [%d]", err_init);
        return NGX_ERROR;
    }

    return NGX_OK;
}

void bch_location_shutdown(ngx_log_t* log, bch_loc_ctx* ctx) {
    if (NULL != ctx->shutdown_fun) {
        ctx->shutdown_fun();
    } else {
        ngx_log_error(NGX_LOG_ERR, log, 0, "bch_location_shutdown:"
                " shutdown callback not available, libname [%s]", ctx->libname.data);
    }
}
