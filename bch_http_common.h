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
 * File:   bch_http_common.h
 * Author: alex
 *
 * Created on February 2, 2021, 10:28 PM
 */

#ifndef BCH_HTTP_COMMON_H
#define BCH_HTTP_COMMON_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t bch_send_buffer(ngx_http_request_t* r, ngx_buf_t* buf);

#endif /* BCH_HTTP_COMMON_H */

