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
 * File:   bch_request_handler.c
 * Author: alex
 *
 * Created on February 2, 2021, 12:38 PM
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "bch_request_handler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jansson.h"

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

static json_t* read_headers(ngx_http_headers_in_t* headers_in) {
    ngx_list_part_t* part = &headers_in->headers.part;
    ngx_table_elt_t* elts = part->elts;

    json_t* res = json_object();

    for (size_t i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            elts = part->elts;
            i = 0;
        }

        ngx_str_t key = elts[i].key;
        ngx_str_t value = elts[i].value;

        json_t* key_json = json_stringn((const char*) key.data, key.len);
        if (NULL != key_json) {
            const char* key_st = json_string_value(key_json);
            json_t* value_json = json_stringn((const char*) value.data, value.len);
            if (NULL != value_json) {
                json_object_set_new(res, key_st, value_json);
            }
            json_decref(key_json);
        }
    }

    return res;
}

static void json_set_ngx_string(json_t* obj, const char* key, ngx_str_t str) {
    json_t* jst = json_stringn((const char*) str.data, str.len);
    if (NULL != jst) {
        json_object_set_new(obj, key, jst);
    } else {
        json_t* empty = json_stringn("", 0);
        json_object_set_new(obj, key, empty);
    }
}

static json_t* create_meta(ngx_http_request_t* r) {
    json_t* res = json_object();
    json_set_ngx_string(res, "uri", r->uri);
    json_set_ngx_string(res, "args", r->args);
    json_set_ngx_string(res, "unparsedUri", r->unparsed_uri);
    json_set_ngx_string(res, "method", r->method_name);
    json_set_ngx_string(res, "protocol", r->http_protocol);
    if (NULL == r->request_body->temp_file) {
        json_object_set_new(res, "dataTempFile", json_null());
    } else {
        ngx_str_t path = r->request_body->temp_file->file.name;
        json_t* path_json = json_stringn((const char*) path.data, path.len);
        if (NULL != path_json) {
            json_object_set_new(res, "dataTempFile", path_json);
        } else { // cannot happen under normal circumstances, lets not crash
            json_object_set_new(res, "dataTempFile", json_null());
        }
    }

    json_t* headers = read_headers(&r->headers_in);
    json_object_set_new(res, "headers", headers);

    return res;
}

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

ngx_int_t init(ngx_log_t* log, bch_loc_ctx* ctx) {
    // load handler shared lib
    if (0 == ctx->libname.len) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "bch_request_handler: handler shared library not specified");
        return NGX_ERROR;
    }

    char* libname_noesc = unescape_spaces(ctx->libname);
    if (NULL == libname_noesc) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "bch_request_handler: alloc failed, size [%d]", ctx->libname.len);
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
                "bch_request_handler: alloc failed, size [%d]", ctx->appconf.len);
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
                "bch_request_handler: application init error, code [%d]", err_init);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void body_handler(ngx_http_request_t* r) {
    if (NULL == r->request_body) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "bch_request_handler: cannot access request body");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    bch_loc_ctx* ctx = ngx_http_get_module_loc_conf(r, ngx_http_background_content_handler_module);
    if (NULL == ctx) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "bch_request_handler: cannot access location context");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (NULL == ctx->receive_request_fun) {
        ngx_int_t err_init = init(r->connection->log, ctx);
        if (NGX_OK != err_init)  {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    // prepare meta
    json_t* meta = create_meta(r);
    char* dumped = json_dumps(meta, JSON_INDENT(4));
    json_decref(meta);

    // prepare data
    char* data = NULL;
    int data_len = 0;
    if (NULL == r->request_body->temp_file) {
        ngx_chain_t* in = r->request_body->bufs;
        if (NULL != in && NULL != in->buf) {
            data = (char*) in->buf->pos;
            data_len = in->buf->last - in->buf->pos;
        }
    }

    // prepare request
    bch_req* request = ngx_pcalloc(r->pool, sizeof(bch_req));
    if (NULL == request) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "bch_request_handler: error allocating buffer, size: [%l]", sizeof(bch_req));
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    request->r = r;
    request->ctx = ctx;

    // call handler
    int err_handler = ctx->receive_request_fun(request, dumped, strlen(dumped), data, data_len);
    free(dumped);
    if (0 != err_handler) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "bch_request_handler: 'bch_receive_request' call returned error, code: [%d]", err_handler);
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
}

ngx_int_t bch_request_handler(ngx_http_request_t* r) {
    // http://mailman.nginx.org/pipermail/nginx/2007-August/001559.html
    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;
    r->request_body_file_log_level = 0;

    ngx_int_t rc = ngx_http_read_client_request_body(r, body_handler);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}

