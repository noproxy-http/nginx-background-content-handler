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
 * File:   ngx_http_bch_module.c
 * Author: alex
 *
 * Created on January 31, 2021, 11:51 AM
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "bch_data.h"
#include "bch_dlopen.h"
#include "bch_http_notify_callback.h"
#include "bch_http_notify_handler.h"
#include "bch_location_lifecycle.h"
#include "bch_request_handler.h"

#ifndef _WIN32
#include "bch_selfpipe_create.h"

int bch_selfpipe_fd_in = 0;
int bch_selfpipe_fd_out = 0;
#endif //!_WIN32

static ngx_int_t on_process_init(ngx_cycle_t* cycle) {

#ifndef _WIN32
    ngx_int_t err_create = bch_selfpipe_create(cycle, &bch_selfpipe_fd_in, &bch_selfpipe_fd_out);
    if (NGX_OK != err_create) {
        return NGX_ERROR;
    }
#endif //!_WIN32

    bch_main_ctx* mctx = ((ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index])->
            main_conf[ngx_http_background_content_handler_module.ctx_index];

    for (size_t i = 0; i < mctx->locations_count; i++) {
        bch_loc_ctx* ctx = mctx->locations[i];
        ngx_int_t err_init = bch_location_init(cycle->log, ctx);
        if (NGX_OK != err_init) {
            for (size_t j = 0; j < i; j++) {
                bch_loc_ctx* sctx = mctx->locations[j];
                bch_location_shutdown(cycle->log, sctx);
            }
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static void on_process_shutdown(ngx_cycle_t* cycle) {

    bch_main_ctx* mctx = ((ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index])->
            main_conf[ngx_http_background_content_handler_module.ctx_index];

    for (size_t i = 0; i < mctx->locations_count; i++) {
        bch_loc_ctx* ctx = mctx->locations[i];
        if (NULL != ctx->receive_request_fun) {
            bch_location_shutdown(cycle->log, ctx);
        }
    }
}

static void* bch_create_main_conf(ngx_conf_t* cf) {
    bch_main_ctx* mctx = ngx_pcalloc(cf->pool, sizeof(bch_main_ctx));
    if (NULL == mctx) {
        return NGX_CONF_ERROR;
    }
    return mctx;
}

static char* bch_init_main_conf(ngx_conf_t* cf, void *conf) {
    bch_main_ctx* mctx = conf;

    mctx->locations = NULL;
    mctx->locations_count = 0;

    return NGX_CONF_OK;
}

static void* bch_create_loc_conf(ngx_conf_t* cf) {
    bch_loc_ctx* ctx = ngx_pcalloc(cf->pool, sizeof(bch_loc_ctx));
    if (NULL == ctx) {
        return NGX_CONF_ERROR;
    }
    ctx->deplibs = ngx_array_create(cf->pool, 0, sizeof(ngx_str_t));
    if (NULL == ctx->deplibs) {
        return NGX_CONF_ERROR;
    }

    return ctx;
}

static char* conf_background_content_handler(ngx_conf_t *cf, ngx_command_t* cmd, void *conf) {
    ngx_http_core_loc_conf_t* clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = bch_request_handler;

    bch_loc_ctx* ctx = conf;
    ngx_str_t* elts = cf->args->elts;
    ctx->libname = elts[1];
    return NGX_CONF_OK;
}

static char* conf_background_content_handler_deplibs(ngx_conf_t *cf, ngx_command_t* cmd, void *conf) {
    bch_loc_ctx* ctx = conf;
    ngx_array_destroy(ctx->deplibs);
    ctx->deplibs = ngx_array_create(cf->pool, cf->args->nelts - 1, sizeof(ngx_str_t));
    if (NULL == ctx->deplibs) {
        return NGX_CONF_ERROR;
    }
    ngx_str_t* elts = cf->args->elts;
    for (size_t i = 1; i < cf->args->nelts; i++) {
        ngx_str_t* el = ngx_array_push(ctx->deplibs);
        if (NULL == el) {
            return NGX_CONF_ERROR;
        }
        *el = elts[i];
    }
    return NGX_CONF_OK;
}

static char* conf_background_content_handler_config(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    bch_loc_ctx* ctx = conf;
    ngx_str_t* elts = cf->args->elts;
    ctx->appconf = elts[1];
    return NGX_CONF_OK;
}

static char* conf_background_content_handler_notify_port(ngx_conf_t *cf, ngx_command_t* cmd, void *conf) {
    bch_loc_ctx* ctx = conf;
    ngx_str_t* elts = cf->args->elts;
    ngx_str_t* st = &elts[1];

    char* endptr;
    long port = strtol((char*) st->data, &endptr, 0);
    if (((char*)st->data) + st->len != endptr || port < 0 || port > 1<<16) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "background_content_handler_notify_port: invalid port number specified,"
                " value: [%s]", st->data);
        return NGX_CONF_ERROR;
    }

    ctx->notify_port = port;
    return NGX_CONF_OK;
}

static char* conf_background_content_handler_notify(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t* clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = bch_http_notify_handler;

    return NGX_CONF_OK;
}

static char* bch_merge_loc_conf(ngx_conf_t* cf, void* parent, void* conf) {
    bch_loc_ctx* ctx = conf;

    // add location context to main context
    if (ctx->libname.len > 0) {
        bch_main_ctx* mctx = ((ngx_http_conf_ctx_t *) cf->ctx)->
                main_conf[ngx_http_background_content_handler_module.ctx_index];
        int exists = 0;
        for (size_t i = 0; i < mctx->locations_count; i++) {
            if (mctx->locations[i] == ctx) {
                exists = 1;
                break;
            }
        }
        if (!exists) {

            // check handler lib can be loaded
            ngx_int_t err_load = bch_location_check_dyload(cf->log, ctx);
            if (NGX_OK != err_load) {
                return NGX_CONF_ERROR;
            }

            // add location
            size_t count = mctx->locations_count + 1;
            bch_loc_ctx** locs = ngx_pcalloc(cf->pool, sizeof(bch_loc_ctx*) * count);
            for (size_t i = 0; i < mctx->locations_count; i++) {
                locs[i] = mctx->locations[i];
            }
            locs[count - 1] = ctx;
            if (mctx->locations_count > 0) {
                ngx_pfree(cf->pool, mctx->locations);
            }
            mctx->locations = locs;
            mctx->locations_count = count;

        }
    }

    return NGX_CONF_OK;
}

static ngx_command_t conf_desc[] = {

    { ngx_string("background_content_handler"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      conf_background_content_handler,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("background_content_handler_deplibs"),
      NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      conf_background_content_handler_deplibs,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("background_content_handler_config"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      conf_background_content_handler_config,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("background_content_handler_notify_port"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      conf_background_content_handler_notify_port,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("background_content_handler_notify"),
      NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
      conf_background_content_handler_notify,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    ngx_null_command /* command termination */
};

static ngx_http_module_t module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    bch_create_main_conf, /* create main configuration */
    bch_init_main_conf, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    bch_create_loc_conf, /* create location configuration */
    bch_merge_loc_conf /* merge location configuration */
};

ngx_module_t ngx_http_background_content_handler_module = {
    NGX_MODULE_V1,
    &module_ctx, /* module context */
    conf_desc, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    on_process_init, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    on_process_shutdown, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};
