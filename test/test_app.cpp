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
 * File:   test_app.cpp
 * Author: alex
 *
 * Created on February 3, 2021, 10:38 AM
 */

#include "bch_functions.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <thread>


namespace { // anonymous

bch_send_response_type send_response = nullptr;

} // namespace

int bch_initialize(bch_send_response_type response_callback,
        const char* hanler_config, int hanler_config_len) {
    
    send_response = response_callback;
    
    auto str = std::string(hanler_config, static_cast<size_t>(hanler_config_len));
    std::cerr << "conf: " << str << std::endl;

    return 0;
}

int bch_receive_request(void* request,
        const char* metadata, int metadata_len,
        const char* data, int data_len) {
    
    std::cerr << "request: " << reinterpret_cast<int64_t>(request) << std::endl;
    auto meta = std::string(metadata, static_cast<size_t>(metadata_len));
    //std::cerr << "meta: " << meta << std::endl;
    auto data_st = nullptr != data ? std::string(data, static_cast<size_t>(data_len)) : "";
    std::cerr << "data_len: " << data_st.length() << std::endl;

    std::thread([request, meta, data_st] () {
        std::cerr << "notifying ..."  << std::endl;
        int err = send_response(request, 200, "{}", 2, meta.c_str(), meta.length());
        std::cerr << "notified: " << err  << std::endl;
    }).detach();

    return 0;
}

