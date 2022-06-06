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
 * File:   bch_location_lifecycle.h
 * Author: alex
 *
 * Created on March 13, 2021, 12:23 PM
 */

#ifndef BCH_LOCATION_LIFECYCLE_H
#define BCH_LOCATION_LIFECYCLE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "bch_data.h"

char* bch_unescape_spaces(ngx_log_t* log, ngx_str_t str);

ngx_int_t bch_location_check_dyload(ngx_log_t* log, bch_loc_ctx* ctx);

ngx_int_t bch_location_init(ngx_log_t* log, bch_loc_ctx* ctx);

void bch_location_shutdown(ngx_log_t* log, bch_loc_ctx* ctx);

#endif /* BCH_LOCATION_LIFECYCLE_H */

