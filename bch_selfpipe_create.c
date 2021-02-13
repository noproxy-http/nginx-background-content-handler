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
 * File:   bch_selfpipe_create.c
 * Author: alex
 *
 * Created on February 13, 2021, 6:24 AM
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifndef _WIN32
#include <ngx_channel.h>

#include "bch_selfpipe_create.h"

#include <errno.h>
#include <unistd.h>

#include "bch_selfpipe_notify_handler.h"

ngx_int_t bch_selfpipe_create(ngx_cycle_t* cycle, int* fd1_out, int* fd2_out) {

    // create pipe
    int fds[2];
    int err = pipe(fds);
    if (0 != err) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                "bch_selfpipe_notify: cannot create selfpipe, error: [%d]", errno);
        return NGX_ERROR;
    }

    // make descriptors non-blocking
    int err_fds1_nb = ngx_nonblocking(fds[0]);
    if (-1 == err_fds1_nb) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                "bch_selfpipe_notify: selfpipe fd1 non-blocking failed, error: [%d]", err_fds1_nb);
        return NGX_ERROR;
    }
    int err_fds2_nb = ngx_nonblocking(fds[1]);
    if (-1 == err_fds2_nb) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                "bch_selfpipe_notify: selfpipe fd2 non-blocking failed, error: [%d]", err_fds2_nb);
        return NGX_ERROR;
    }

    // register listener on a pipe
    ngx_int_t rc = ngx_add_channel_event(cycle, fds[0], NGX_READ_EVENT, bch_selfpipe_notify_handler);
    if (NGX_OK != rc) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                "bch_selfpipe_notify: selfpipe handler registration failed, error: [%d]", rc);
        return NGX_ERROR;
    }

    *fd1_out = fds[1];
    *fd2_out = fds[0];

    return NGX_OK;
}

#endif // !_WIN32