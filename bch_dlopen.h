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
 * File:   bch_dlopen.h
 * Author: alex
 *
 * Created on January 31, 2021, 11:53 AM
 */

#ifndef BCH_DLOPEN_H
#define BCH_DLOPEN_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

void* bch_dyload_library(ngx_log_t* log, const char* libname);

void* bch_dyload_symbol(ngx_log_t* log, void* lib, const char* symbol);

int bch_dyload_close(ngx_log_t* log, void* lib);

#endif /* BCH_DLOPEN_H */

