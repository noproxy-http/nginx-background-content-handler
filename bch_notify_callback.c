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
 * File:   bch_notify_callback.c
 * Author: alex
 *
 * Created on February 13, 2021, 6:55 AM
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "bch_notify_callback.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "jansson.h"

#ifdef _WIN32
#pragma warning( disable: 4706 )
#endif // _WIN32
static json_t* parse_headers(const char* headers, int headers_len) {
    // parse
    size_t ulen = headers_len;
    json_t* root = json_loadb(headers, ulen, JSON_REJECT_DUPLICATES, NULL);
    if (NULL == root) {
        return NULL;
    }

    // validate
    if (!json_is_object(root)) {
        json_decref(root);
        return NULL;
    }

    const char *key;
    json_t *value;
    json_object_foreach(root, key, value) {
        if (0 == strlen(key) || !json_is_string(value)) {
            json_decref(root);
            return NULL;
        }
    }

    return root;
#ifdef _WIN32
#pragma warning( default: 4706 )
#endif // _WIN32
}

bch_resp* bch_create_resp(void* request, int http_status,
        const char* headers, int headers_len,
        char* data, int data_len) {
    if (NULL == request) {
        return NULL;
    }
    if (http_status < 200 || http_status > 599) {
        return NULL;
    }

    if (data_len < 0) {
        return NULL;
    }

    json_t* headers_json = parse_headers(headers, headers_len);
    if (NULL == headers_json) {
        return NULL;
    }
    bch_resp* resp = malloc(sizeof(bch_resp));
    if (NULL == resp) {
        json_decref(headers_json);
        return NULL;
    }

    resp->request = request;
    resp->status = http_status;
    resp->headers = headers_json;
    resp->data = (u_char*) data;
    resp->data_len = (size_t) data_len;

    return resp;
}

#include "jansson.h"