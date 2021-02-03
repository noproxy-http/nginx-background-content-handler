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

#include "bch_request_handler.h"

#include <stdio.h>
#include <stdlib.h>

#include "jansson.h"

#include "bch_dlopen.h"
#include "bch_functions.h"
#include "bch_http_notify.h"

typedef int (*bch_initialize_type)(
        bch_send_response_type response_callback,
        const char* hanler_config,
        int hanler_config_len);

typedef int (*bch_receive_request_type)(
        void* request,
        const char* metadata, int metadata_len,
        const char* data, int data_len);

static bch_receive_request_type bch_receive_request_fun = NULL;

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

static json_t* read_meta(ngx_http_request_t* r) {
    json_t* res = json_object();
    json_t* handle = json_integer((long long) r);
    if (NULL != handle) { // cannot happen
        json_object_set_new(res, "requestHandle", handle);
    }
    json_set_ngx_string(res, "uri", r->uri);
    json_set_ngx_string(res, "args", r->args);
    json_set_ngx_string(res, "unparsedUri", r->unparsed_uri);
    json_set_ngx_string(res, "method", r->method_name);
    json_set_ngx_string(res, "protocol", r->http_protocol);
    return res;
}

static void body_handler(ngx_http_request_t* r) {

    if (NULL == r->request_body) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    json_t* meta = read_meta(r);
    json_t* headers = read_headers(&r->headers_in);
    json_object_set_new(meta, "headers", headers);

    char* dumped = json_dumps(meta, JSON_INDENT(4));
    json_decref(meta);
    char* data = NULL;
    int data_len = 0;
    ngx_chain_t* in = r->request_body->bufs;
    if (NULL != in && NULL != in->buf) {
        data = (char*) in->buf->pos;
        data_len = in->buf->last - in->buf->pos;
    }

    int err_handle = bch_receive_request_fun(r, dumped, strlen(dumped), data, data_len);
    free(dumped);
    if (0 != err_handle) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'submit_json_request' call returned error, code: [%d]", err_handle);
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
}

ngx_int_t bch_request_handler_initialize(ngx_log_t* log, ngx_str_t libname) {
    // load handler shared lib
    if (0 == libname.len) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "handler shared library not specified");
        return NGX_ERROR;
    }

    // load lib, conf values are NUL-terminated
    void* lib = bch_dyload_library(log, (const char*)libname.data);
    if (NULL == lib) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "cannot load shared library, name: [%s]", libname.data);
        return NGX_ERROR;
    }

    // lookup init
    bch_initialize_type init_fun = bch_dyload_symbol(log, lib, "bch_initialize");
    if (NULL == init_fun) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "cannot find symbol 'bch_initialize' in shared library, name: [%s]", libname.data);
        return NGX_ERROR;
    }

    // lookup receive
    bch_receive_request_fun = bch_dyload_symbol(log, lib, "bch_receive_request");
    if (NULL == bch_receive_request_fun) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "cannot find symbol 'bch_receive_request' in shared library, name: [%s]", libname.data);
        return NGX_ERROR;
    }

    // call init
    const char* appconf = "/foo/bar/app.conf";
    int err_init = init_fun(bch_http_notify_callback, appconf, strlen(appconf));
    if (0 != err_init) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "'bch_request_handler_initialize': application init error, code [%d]", err_init);
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t bch_request_handler(ngx_http_request_t *r) {

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

