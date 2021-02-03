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
 * File:   bch_dlopen_unix.c
 * Author: alex
 *
 * Created on January 31, 2021, 11:53 AM
 */

#include <errno.h>
#include <dlfcn.h>

void* bch_dyload_library(ngx_log_t* log, const char* libname) {
    if (NULL == libname) {
        ngx_log_error(NGX_LOG_ERR,
                log, 0, "bch_dyload_library: invalid 'null' libname specified");
        return NULL;
    }
    void* lib = dlopen(libname, RTLD_LAZY);
    if (NULL == lib) {
        ngx_log_error(NGX_LOG_ERR,
                log, 0, "bch_dyload_library: cannot load library, name: [%s], code: [%d]",
                        libname, errno);
        return NULL;
    }
    return lib;
}

void* bch_dyload_symbol(ngx_log_t* log, void* lib, const char* symbol) {
    if (NULL == lib) {
        ngx_log_error(NGX_LOG_ERR,
                log, 0, "bch_dyload_symbol: invalid 'null' lib specified");
        return NULL;
    }
    if (NULL == symbol) {
        ngx_log_error(NGX_LOG_ERR,
                log, 0, "bch_dyload_symbol: invalid 'null' symbol specified");
        return NULL;
    }
    void* sym = dlsym(lib, symbol);
    if (NULL == sym) {
        ngx_log_error(NGX_LOG_ERR,
                log, 0, "bch_dyload_symbol: cannot load symbol, name: [%s], code: [%d]",
                        symbol, errno);
    }
}

