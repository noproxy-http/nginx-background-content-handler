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
 * File:   bch_selfpipe_notify_callback.c
 * Author: alex
 *
 * Created on February 13, 2021, 6:49 AM
 */

#ifndef _WIN32

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "bch_selfpipe_notify_callback.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "jansson.h"

#include "bch_data.h"
#include "bch_notify_callback.h"

static int write_to_pipe(bch_resp* resp) {
    for (;;) {
        int written = write(bch_selfpipe_fd_in, (void*) &resp, sizeof(resp));
        if (sizeof(resp) == written) {
            return 0;
        } else if (-1 == written) {
            // note: spinning should not happen
            if (EINTR == errno || EAGAIN == errno || EWOULDBLOCK == errno) {
                continue;
            } else {
                return 1;
            }
        } else {
            return -1;
        }
    }
}

int bch_selfpipe_notify_callback(void* request, int http_status,
        const char* headers, int headers_len,
        char* data, int data_len) {

    // create resp
    bch_resp* resp = bch_create_resp(request, http_status, headers, headers_len, data, data_len);
    if (NULL == resp) {
        return -1;
    }
    bch_loc_ctx* ctx = resp->request->ctx;

    // write to pipe
    int err = write_to_pipe(resp);
    if (0 != err) {
        if (NULL != data) {
            ctx->free_response_data_fun(data);
        }
        json_decref(resp->headers);
        free(resp);
    }

    return err;
}

#endif // !_WIN32
