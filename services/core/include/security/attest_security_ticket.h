/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef __ATTEST_SECURITY_TICKET_H__
#define __ATTEST_SECURITY_TICKET_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* End of #ifdef __cplusplus */

#define MAX_TICKET_LEN 48
#define MIN_TICKET_LEN 32

int32_t WriteTicketToDevice(const char* ticket, uint8_t len);

int32_t ReadTicketFromDevice(char* ticket, uint8_t len);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif