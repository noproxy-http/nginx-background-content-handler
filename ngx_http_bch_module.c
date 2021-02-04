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

#include "bch_http_notify.h"
#include "bch_http_notify_handler.h"
#include "bch_request_handler.h"

static ngx_int_t initialize(ngx_cycle_t* cycle) {
    ngx_str_t st = ngx_string("/home/alex/projects/nginx/nginx-background-content-handler/test/build/libtest_app.so\0");
    bch_request_handler_init(cycle->log, st);
    bch_http_notify_init(8888);
}

static char* conf_background_content_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    /* install the handler. */
    ngx_http_core_loc_conf_t* clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = bch_request_handler;
    return NGX_CONF_OK;
}

static char* conf_background_content_handler_notify(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    /* install the handler. */
    ngx_http_core_loc_conf_t* clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = bch_http_notify_handler;
    return NGX_CONF_OK;
}

static ngx_command_t conf_desc[] = {

    { ngx_string("background_content_handler"), /* directive */
      NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, /* location context and arguments count*/
      conf_background_content_handler, /* configuration setup function */
      NGX_HTTP_LOC_CONF_OFFSET, /* Conf offset. */
      0, /* No offset when storing the module configuration on struct. */
      NULL},

    { ngx_string("background_content_handler_notify"), /* directive */
      NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, /* location context and arguments count*/
      conf_background_content_handler_notify, /* configuration setup function */
      NGX_HTTP_LOC_CONF_OFFSET, /* Conf offset. */
      0, /* No offset when storing the module configuration on struct. */
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

    NULL, /* create location configuration */
    NULL /* merge location configuration */
};

ngx_module_t ngx_http_background_content_handler_module = {
    NGX_MODULE_V1,
    &module_ctx, /* module context */
    conf_desc, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    initialize, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

