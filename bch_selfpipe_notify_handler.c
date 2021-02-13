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
 * File:   bch_selfpipe_notify_handler.c
 * Author: alex
 *
 * Created on February 13, 2021, 7:13 AM
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifndef _WIN32
#include <ngx_channel.h>

#include "bch_selfpipe_notify_handler.h"

#include <errno.h>
#include <unistd.h>

#include "bch_data.h"
#include "bch_notify_handler.h"

static bch_resp* read_resp(ngx_connection_t* c, int* err) {

    for(;;) {

        bch_resp* resp;
        int rread = read(c->fd, &resp, sizeof(resp));

        if (-1 == rread) {
            if (errno == EINTR) {
                continue; // should not spin here
            } else if (EAGAIN == errno || EWOULDBLOCK == errno) {
                return NULL;
            }
        }

        if (rread <= 0) {
           *err = 1;
           return NULL;
        }

        return resp;
    }
}

void bch_selfpipe_notify_handler(ngx_event_t* ev) {

    ngx_connection_t* c = (ngx_connection_t*) ev->data;
    ngx_int_t err_ev = ngx_handle_read_event(ev, 0);
    if (err_ev != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ev->log, 0,
                "bch_selfpipe_notify: cannot read selfpipe event, error: [%d]", err_ev);
        return;
    }

    if (ev->timedout) {
        ev->timedout = 0;
        return;
    }

    int err = 0;
    bch_resp* resp = read_resp(c, &err);
    if (0 != err) {
        // This was copied from ngx_channel_handler(): for epoll, we need to call
        // ngx_del_conn(). Sadly, no documentation as to why.
        if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {
          ngx_del_conn(c, 0);
        }
        ngx_close_connection(c);
        ngx_del_event(ev, NGX_READ_EVENT, 0);
        return;
    }

    if (NULL != resp) {
        bch_loc_ctx* ctx = resp->request->ctx;
        u_char* data = resp->data;

        ngx_int_t status = bch_send_resp_to_client(resp);

        json_decref(resp->headers);
        free(resp);
        if (NGX_HTTP_OK != status && NGX_HTTP_BAD_GATEWAY != status && NULL != data) {
            ctx->free_response_data_fun(data);
        }
    }
}

#endif // !_WIN32