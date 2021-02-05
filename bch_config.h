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
 * File:   bch_config.h
 * Author: alex
 *
 * Created on February 4, 2021, 7:43 PM
 */

#ifndef BCH_CONFIG_H
#define BCH_CONFIG_H

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct bch_config {
    ngx_str_t libname;
    ngx_str_t appconf;
} bch_config;


#endif /* BCH_CONFIG_H */

