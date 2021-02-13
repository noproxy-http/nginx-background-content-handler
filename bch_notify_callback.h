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
 * File:   bch_notify_callback.h
 * Author: alex
 *
 * Created on February 13, 2021, 6:53 AM
 */
#ifndef BCH_NOTIFY_CALLBACK_H
#define BCH_NOTIFY_CALLBACK_H

#include "bch_data.h"

bch_resp* bch_create_resp(void* request, int http_status,
        const char* headers, int headers_len,
        char* data, int data_len);

#endif /* BCH_NOTIFY_CALLBACK_H */

