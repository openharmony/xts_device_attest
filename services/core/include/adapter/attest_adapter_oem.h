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

#ifndef ATTEST_ADAPTER_OEM_H
#define ATTEST_ADAPTER_OEM_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define AUTH_RESULT_PATH "/data/device_attest" // 具体读写路径待和浩哥讨论
#define AUTH_STATUS_FILE_NAME "auth_status"
#define AUTH_RESULT_CODE_FILE_NAME "auth_result_code"
#define TICKET_FILE_NAME "ticket"
#define RESET_FLAG_FILE_NAME "reset_flag"
#define NETWORK_CONFIG_FILE_NAME "network_config.json"

int32_t OEMWriteTicket(const TicketInfo* ticketInfo);

int32_t OEMReadTicket(TicketInfo* ticketInfo);

int32_t OEMWriteAuthStatus(const char* data, uint32_t len);

int32_t OEMReadAuthStatus(char* buffer, uint32_t bufferLen);

int32_t OEMGetAuthStatusFileSize(uint32_t* len);

int32_t OEMCreateResetFlag(void);

bool OEMIsResetFlagExist(void);

int32_t OEMReadNetworkConfig(char* buffer, uint32_t bufferLen);

int32_t OEMWriteAuthResultCode(const char* data, uint32_t len);

int32_t OEMReadAuthResultCode(char* buffer, uint32_t bufferLen);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif

