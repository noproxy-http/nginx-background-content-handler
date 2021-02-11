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
#include "bch_http_notify_callback.h"
#include "bch_http_notify_handler.h"
#include "bch_request_handler.h"

static void* bch_create_loc_conf(ngx_conf_t* cf) {
    bch_loc_ctx* ctx = ngx_pcalloc(cf->pool, sizeof(bch_loc_ctx));
    if (NULL == ctx) {
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
                "'background_content_handler_notify_port': invalid port number specified,"
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

    (void) ctx;
    // todo: validation

    return NGX_CONF_OK;
}

static ngx_command_t conf_desc[] = {

    { ngx_string("background_content_handler"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      conf_background_content_handler,
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

    NULL, /* create main configuration */
    NULL, /* init main configuration */

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
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};
