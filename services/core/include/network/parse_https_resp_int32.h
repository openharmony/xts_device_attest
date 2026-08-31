/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PARSE_HTTPS_RESP_INT32_H
#define PARSE_HTTPS_RESP_INT32_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parse a decimal int32 from an untrusted HTTPS status / Content-Length field.
 * Whole-token: reject empty, overflow, signs, and leftover junk such as "200abc".
 * Trailing HTTP separators (space / tab / CR / LF) after the digits are allowed
 * so "200 OK" and "123\\r\\n" still parse.
 */
bool ParseHttpsRespInt32(const char *text, int32_t *out);

#ifdef __cplusplus
}
#endif

#endif /* PARSE_HTTPS_RESP_INT32_H */
