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
 * File:   bch_functions.h
 * Author: alex
 *
 * Created on February 2, 2021, 12:45 PM
 */

#ifndef BCH_FUNCTIONS_H
#define BCH_FUNCTIONS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*bch_send_response_type)(
        void* request,
        int http_status,
        const char* headers, int headers_len,
        char* data, int data_len);

#ifdef _WIN32
__declspec( dllexport )
#endif // _WIN32
int bch_initialize(
        bch_send_response_type response_callback,
        const char* hanler_config,
        int hanler_config_len);

#ifdef _WIN32
__declspec( dllexport )
#endif // _WIN32
int bch_receive_request(
        void* request,
        const char* metadata, int metadata_len,
        const char* data, int data_len);

#ifdef _WIN32
__declspec( dllexport )
#endif // _WIN32
void bch_free_response_data(
        void* data);

#ifdef _WIN32
__declspec( dllexport )
#endif // _WIN32
void bch_shutdown();

#ifdef __cplusplus
}
#endif

#endif /* BCH_FUNCTIONS_H */

