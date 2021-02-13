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
 * File:   bch_notify_handler.c
 * Author: alex
 *
 * Created on February 13, 2021, 7:35 AM
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "bch_notify_handler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jansson.h"

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#else //_WIN32
#include <windows.h>
#define close CloseHandle
#endif // !_WIN32

#include "bch_data.h"

static const char BCH_HEADER_PREFIX[] = "X-Background-Content-Handler";
static const char BCH_HEADER_DATA_FILE[] = "X-Background-Content-Handler-Data-File";

static ngx_int_t add_single_header(ngx_http_request_t* r, const char* key_in, const char* value_in) {
    // copy key
    ngx_str_t key;
    key.len = strlen(key_in);
    key.data = ngx_pcalloc(r->pool, key.len);
    if (NULL == key.data) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': pool allocation error, size: [%l]", key.len);
        return NGX_ERROR;
    }
    memcpy(key.data, key_in, key.len);

    // copy value
    ngx_str_t value;
    value.len = strlen(value_in);
    value.data = ngx_pcalloc(r->pool, value.len);
    if (NULL == value.data) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': pool allocation error, size: [%l]", value.len);
        return NGX_ERROR;
    }
    memcpy(value.data, value_in, value.len);

    // set header
    ngx_table_elt_t* hout = ngx_list_push(&r->headers_out.headers);
    if (hout == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': header allocation error");
        return NGX_ERROR;
    }
    hout->key = key;
    hout->value = value;
    hout->hash = 1;

    return NGX_OK;
}

#ifdef _WIN32
#pragma warning( disable: 4706 )
#endif // _WIN32
static ngx_int_t add_headers(bch_resp* resp, const char** data_file_out) {
    ngx_http_request_t* r = resp->request->r;
    const char *key;
    json_t *value;
    json_object_foreach(resp->headers, key, value) {
        const char* val = json_string_value(value);
        size_t key_len = strlen(key);
        size_t pref_len = sizeof(BCH_HEADER_PREFIX) - 1;
        if (key_len < pref_len || 0 != strncmp(BCH_HEADER_PREFIX, key, pref_len)) {
            ngx_int_t err_set = add_single_header(r, key, val);
            if (NGX_OK != err_set) {
                return err_set;
            }
        } else { // internal header
            size_t hdf_len = sizeof(BCH_HEADER_DATA_FILE) - 1;
            if (key_len == hdf_len && 0 == strncmp(BCH_HEADER_DATA_FILE, key, hdf_len)) {
                *data_file_out = val;
            } else {
                // ignore
            }
        }
    }
    return NGX_OK;
#ifdef _WIN32
#pragma warning( default: 4706 )
#endif // _WIN32
}

#ifdef _WIN32
static int widen(const char* st, wchar_t** out) {
    size_t len = strlen(st);
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, st, len, NULL, 0);
    if (0 == size_needed) {
        return GetLastError();
    }
    size_t buf_len = sizeof(wchar_t) * (size_needed + 1);
    wchar_t* buf = malloc(buf_len);
    if (NULL == buf) {
        return -1;
    }
    memset(buf, '\0', buf_len);
    int chars_copied = MultiByteToWideChar(CP_UTF8, 0, st, len, buf, size_needed);
    if (chars_copied != size_needed) {
        free(buf);
        return GetLastError();
    }
    *out = buf;
    return 0;
}
#endif // _WIN32

static ngx_temp_file_t* create_temp_file(ngx_http_request_t* r, const char* data_file, size_t* data_file_len) {
    // open file
#ifndef _WIN32
    ngx_fd_t fd = open(data_file, O_RDONLY);
    if (-1 == fd) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': cannot open response file, path: [%s]", data_file);
        return NULL;
    }
    struct stat st;
    int err_stat = stat(data_file, &st);
    if (0 != err_stat) {
        close(fd);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': cannot stat response file, path: [%s]", data_file);
        return NULL;
    }
    size_t st_size = st.st_size;
#else // _WIN32
    wchar_t* wname = NULL;
    int err_widen = widen(data_file, &wname);
    if (0 != err_widen) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': file name widen error, code: [%d]", err_widen);
        return NULL;
    }
    HANDLE fd = CreateFileW(wname, GENERIC_READ, 
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == fd) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': cannot open response file, path: [%s]", data_file);
        return NULL;
    }
    LARGE_INTEGER wsize;
    BOOL err_size = GetFileSizeEx(fd, &wsize);
    if (0 == err_size) {
        close(fd);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': cannot stat response file, path: [%s]", data_file);
        return NULL;
    }
    size_t st_size = (size_t) wsize.QuadPart;
#endif //!_WIN32

    // temp file
    ngx_temp_file_t* tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
    if (tf == NULL) {
        close(fd);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': error allocating buffer, size: [%l]", sizeof(ngx_temp_file_t));
        return NULL;
    }
    tf->file.fd = fd;
    tf->file.log = r->connection->log;
    tf->pool = r->pool;
    tf->clean = 1;

    // cleanup
    u_char* name_cleanup = ngx_pcalloc(r->pool, strlen(data_file) + 1);
    if (NULL == name_cleanup) {
        close(fd);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': error allocating buffer, size: [%d]", strlen(data_file) + 1);
        return NULL;
    }
    memcpy(name_cleanup, data_file, strlen(data_file));
    ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) {
        close(fd);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': error creating reponse file cleanup struct]");
        return NULL;
    }
    cln->handler = ngx_pool_delete_file;
    ngx_pool_cleanup_file_t* clnf = cln->data;
    clnf->fd = fd;
    clnf->name = name_cleanup;
    clnf->log = r->connection->log;

    // content size
    *data_file_len = st_size;

    return tf;
}

static ngx_buf_t* create_client_buf(bch_resp* resp, const char* data_file, size_t* data_file_len) {
    ngx_http_request_t* r = resp->request->r;

    ngx_buf_t* buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (NULL == buf) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': pool allocation error, size: [%l]", sizeof(ngx_buf_t));
        return NULL;
    }

    if (NULL == data_file) {
        if (resp->data_len > 0) {
            ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool, sizeof(char*));
            if (cln == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "'bch_http_notify': error creating response data cleanup struct");
                return NULL;
            }
            cln->handler = resp->request->ctx->free_response_data_fun;
            cln->data = resp->data;

            buf->pos = resp->data;
            buf->last = buf->pos + resp->data_len;
            buf->start = buf->pos;
            buf->end = buf->last;
            buf->memory = 1;
        } else {
            buf->pos = 0;
            buf->last = 0;
        }
    } else { // temp file
        ngx_temp_file_t* fi = create_temp_file(r, data_file, data_file_len);
        if (NULL == fi) {
            return NULL;
        }
        buf->file = (ngx_file_t*) fi;
        buf->file_pos = 0;
        buf->file_last = *data_file_len;
        buf->in_file = 1;
        buf->temp_file = 1;
    }

    buf->last_buf = 1;
    return buf;
}

ngx_int_t bch_send_buffer(ngx_http_request_t* r, ngx_buf_t* buf) {
    // send headers
    ngx_int_t err_headers = ngx_http_send_header(r);
    if (NGX_OK != err_headers) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': error sending headers, code: [%d]", err_headers);
        return err_headers;
    }

    // send data
    ngx_chain_t chain;
    chain.buf = buf;
    chain.next = NULL;
    ngx_int_t err_filters = ngx_http_output_filter(r, &chain);
    if (NGX_OK != err_filters && NGX_AGAIN != err_filters) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': error sending data, code: [%d]", err_filters);
        return err_filters;
    }

    return NGX_OK;
}

ngx_int_t bch_send_resp_to_client(bch_resp* resp) {
    ngx_http_request_t* r = resp->request->r;

    if (r->connection->error) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "'bch_http_notify': request already finalized, counter: [%d]", r->count);
        ngx_http_finalize_request(r, NGX_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // headers
    const char* data_file = NULL;
    ngx_int_t err_headers = add_headers(resp, &data_file);
    if (NGX_OK != err_headers) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // data
    size_t data_file_len = 0;
    ngx_buf_t* buf = create_client_buf(resp, data_file, &data_file_len);
    if (NULL == buf) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // send
    r->headers_out.status = resp->status;
    if (NULL == data_file) {
        r->headers_out.content_length_n = resp->data_len;
    } else {
        r->headers_out.content_length_n = data_file_len;
    }

    // finalize
    ngx_int_t err_send = bch_send_buffer(r, buf);
    ngx_connection_t* c = r->connection;
    ngx_int_t rc = NGX_OK == err_send ? NGX_HTTP_OK : NGX_ERROR;
    ngx_http_finalize_request(r, rc);
    if (!c->error) {
        ngx_http_run_posted_requests(c);
    } else {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "'bch_http_notify': client connection error on sending response");
    }
    return rc == NGX_HTTP_OK ? NGX_HTTP_OK : NGX_HTTP_BAD_GATEWAY;
}