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

#include "bch_config.h"
#include "bch_http_notify.h"
#include "bch_http_notify_handler.h"
#include "bch_request_handler.h"

static uint16_t notify_port = 0;
//static char* conf_str = "";

static ngx_int_t request_handler(ngx_http_request_t *r);

static ngx_int_t initialize(ngx_cycle_t* cycle) {
//    ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "process pid: [%d]", getpid());

    ngx_str_t st = ngx_string("/home/alex/projects/nginx/nginx-background-content-handler/test/build/libtest_app.so\0");
    bch_request_handler_init(cycle->log, st);
    bch_http_notify_init(notify_port);
    return NGX_OK;
}

static char* conf_background_content_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    /* install the handler. */
    ngx_http_core_loc_conf_t* clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = request_handler;
    return NGX_CONF_OK;
}

static char* conf_background_content_handler_notify(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    /* install the handler. */
    ngx_http_core_loc_conf_t* clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = bch_http_notify_handler;

    // get notify port
    ngx_str_t* elts = cf->args->elts;
    ngx_str_t* st = &elts[1];

    char* endptr;
    long port = strtol((char*) st->data, &endptr, 0);
    if (((char*)st->data) + st->len != endptr || port < 0 || port > 1<<16) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "'background_content_handler_notify': invalid port number specified,"
                " value: [%s]", st->data);
        return NGX_CONF_ERROR;
    }
    if (0 != notify_port) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "'background_content_handler_notify': duplicate location,"
                " port 1: [%d], port 2: [%d]", notify_port, port);
        return NGX_CONF_ERROR;
    }

    notify_port = port;
    return NGX_CONF_OK;
}

static void* bch_create_loc_conf(ngx_conf_t* cf) {
    bch_config* conf;

    conf = ngx_pcalloc(cf->pool, sizeof(bch_config));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    return conf;
}

static char* bch_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    bch_config *prev = parent;
    bch_config *conf = child;

    ngx_conf_merge_str_value(conf->libname, prev->libname, "");
    ngx_conf_merge_str_value(conf->appconf, prev->appconf, "");

    return NGX_CONF_OK;
}

static ngx_command_t conf_desc[] = {

    { ngx_string("background_content_handler"),
      NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
      conf_background_content_handler,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("background_content_handler_lib"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(bch_config, libname),
      NULL},

    { ngx_string("background_content_handler_config"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(bch_config, appconf),
      NULL},

    { ngx_string("background_content_handler_notify"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
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
    initialize, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t request_handler(ngx_http_request_t *r) {
    bch_config* conf = ngx_http_get_module_loc_conf(r, ngx_http_background_content_handler_module);
    return bch_request_handler(conf, r);
}