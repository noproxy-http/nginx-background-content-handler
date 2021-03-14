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
 * File:   bch_dlopen.c
 * Author: alex
 *
 * Created on January 31, 2021, 11:52 AM
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "bch_dlopen.h"

#ifndef _WIN32


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
    return sym;
}

int bch_dyload_close(ngx_log_t* log, void* lib) {
    if (NULL == lib) {
        ngx_log_error(NGX_LOG_ERR,
                log, 0, "bch_dyload_close: invalid 'null' lib specified");
        return -1;
    }
    int err = dlclose(lib);
    if (0 != err) {
        ngx_log_error(NGX_LOG_ERR,
                log, 0, "bch_dyload_close: close, code: [%d]", err);
        return 1;
    }
    return 0;
}


#else // _WIN32


#include <stdlib.h>
#include <string.h>

#include <windows.h>

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

void* bch_dyload_library(ngx_log_t* log, const char* libname) {
    if (NULL == libname) {
        ngx_log_error(NGX_LOG_ERR,
                log, 0, "bch_dyload_library: invalid 'null' libname specified");
        return NULL;
    }
    wchar_t* wname = NULL;
    int err_widen = widen(libname, &wname);
    if (0 != err_widen) {
        ngx_log_error(NGX_LOG_ERR,
                log, 0, "bch_dyload_library: libname widen error, code: [%d]", err_widen);
        return NULL;
    }

    HMODULE lib = LoadLibraryW(wname);
    free(wname);
    if (NULL == lib) {
        ngx_log_error(NGX_LOG_ERR,
                log, 0, "bch_dyload_library: cannot load library, name: [%s], code: [%d]",
                        libname, GetLastError());
        return NULL;
    }
    return (void*) lib;
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
    FARPROC sym = GetProcAddress((HMODULE) lib, symbol);
    if (NULL == sym) {
        ngx_log_error(NGX_LOG_ERR,
                log, 0, "bch_dyload_symbol: cannot load symbol, name: [%s], code: [%d]",
                        symbol, GetLastError());
    }
    return (void*) sym;
}

int bch_dyload_close(ngx_log_t* log, void* lib) {
    if (NULL == lib) {
        ngx_log_error(NGX_LOG_ERR,
                log, 0, "bch_dyload_close: invalid 'null' lib specified");
        return -1;
    }
    BOOL err = FreeLibrary((HMODULE) lib);
    if (0 == err) {
        ngx_log_error(NGX_LOG_ERR,
                log, 0, "bch_dyload_close: close, code: [%d]", GetLastError());
        return 1;
    }
    return 0;

}

#endif // _WIN32

