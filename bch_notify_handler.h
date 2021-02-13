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
 * File:   bch_notify_handler.h
 * Author: alex
 *
 * Created on February 13, 2021, 7:15 AM
 */

#ifndef BCH_NOTIFY_HANDLER_H
#define BCH_NOTIFY_HANDLER_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "bch_data.h"

ngx_int_t bch_send_buffer(ngx_http_request_t* r, ngx_buf_t* buf);

ngx_int_t bch_send_resp_to_client(bch_resp* resp);

#endif /* BCH_NOTIFY_HANDLER_H */

