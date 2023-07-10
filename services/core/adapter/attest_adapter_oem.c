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

#include <securec.h>
#include "attest_utils_file.h"
#include "attest_adapter_oem.h"

// 是否存在标记
bool OEMIsFlagExist(OEM_FLAG_TYPE type)
{
    bool result = false;
    switch (type) {
        case OEM_FLAG_RESET:
            result = IsFileExist(AUTH_RESULT_PATH, RESET_FLAG_FILE_NAME);
            break;
        default:
            break;
    }
    return result;
}

// 创建标记
int32_t OEMCreateFlag(OEM_FLAG_TYPE type)
{
    int32_t result = ATTEST_ERR;
    switch (type) {
        case OEM_FLAG_RESET:
            result = CreateFile(AUTH_RESULT_PATH, RESET_FLAG_FILE_NAME);
            break;
        default:
            break;
    }
    return result;
}

// 写入认证结果
int32_t OEMWriteAuthStatus(const char* data, uint32_t len)
{
    if (CreateFile(AUTH_RESULT_PATH, AUTH_STATUS_FILE_NAME) != 0) {
        return ATTEST_ERR;
    }
    return WriteFile(AUTH_RESULT_PATH, AUTH_STATUS_FILE_NAME, data, len);
}

// 读取认证结果
int32_t OEMReadAuthStatus(char* buffer, uint32_t bufferLen)
{
    return ReadFile(AUTH_RESULT_PATH, AUTH_STATUS_FILE_NAME, buffer, bufferLen);
}

// 读取认证结果长度
int32_t OEMGetAuthStatusFileSize(uint32_t* len)
{
    return GetFileSize(AUTH_RESULT_PATH, AUTH_STATUS_FILE_NAME, len);
}

// 读取凭据
int32_t OEMReadTicket(TicketInfo* ticketInfo)
{
    char ticket[TICKET_ENCRYPT_LEN + SALT_ENCRYPT_LEN] = {0};
    if (ReadFile(AUTH_RESULT_PATH, TICKET_FILE_NAME, ticket, sizeof(ticket)) != 0) {
        return ATTEST_ERR;
    }
    if (memcpy_s(ticketInfo->ticket, TICKET_ENCRYPT_LEN, ticket, TICKET_ENCRYPT_LEN) != 0 ||
        memcpy_s(ticketInfo->salt, SALT_ENCRYPT_LEN, ticket + TICKET_ENCRYPT_LEN, SALT_ENCRYPT_LEN) != 0) {
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}

// 写入凭据
int32_t OEMWriteTicket(const TicketInfo* ticketInfo)
{
    char ticket[TICKET_ENCRYPT_LEN + SALT_ENCRYPT_LEN] = {0};
    if (memcpy_s(ticket, TICKET_ENCRYPT_LEN, ticketInfo->ticket, TICKET_ENCRYPT_LEN) != 0 ||
        memcpy_s(ticket + TICKET_ENCRYPT_LEN, SALT_ENCRYPT_LEN, ticketInfo->salt, SALT_ENCRYPT_LEN) != 0) {
        return ATTEST_ERR;
    }

    if (CreateFile(AUTH_RESULT_PATH, TICKET_FILE_NAME) != 0) {
        return ATTEST_ERR;
    }
    return WriteFile(AUTH_RESULT_PATH, TICKET_FILE_NAME, ticket, sizeof(ticket));
}

// 是否存在网络配置信息
bool OEMIsNetworkConfigExist(void)
{
    return IsFileExist(AUTH_RESULT_PATH, NETWORK_CONFIG_FILE_NAME);
}

// 写入网络配置信息
int32_t OEMWriteNetworkConfig(const char* buffer, uint32_t bufferLen)
{
    if (CreateFile(AUTH_RESULT_PATH, NETWORK_CONFIG_FILE_NAME) != 0) {
        return ATTEST_ERR;
    }
    return WriteFile(AUTH_RESULT_PATH, NETWORK_CONFIG_FILE_NAME, buffer, bufferLen);
}

// 读取网络配置信息
int32_t OEMReadNetworkConfig(char* buffer, uint32_t bufferLen)
{
    return ReadFile(AUTH_RESULT_PATH, NETWORK_CONFIG_FILE_NAME, buffer, bufferLen);
}

// 读取默认网络配置信息
int32_t OEMReadDefaultNetworkConfig(char* buffer, uint32_t bufferLen)
{
    return ReadFile(ETC_DEVICE_ATTEST_PATH, NETWORK_CONFIG_FILE_NAME, buffer, bufferLen);
}

// 写入认证结果
int32_t OEMWriteAuthResultCode(const char* data, uint32_t len)
{
    if (CreateFile(AUTH_RESULT_PATH, AUTH_RESULT_CODE_FILE_NAME) != 0) {
        return ATTEST_ERR;
    }
    return WriteFile(AUTH_RESULT_PATH, AUTH_RESULT_CODE_FILE_NAME, data, len);
}

// 读取认证结果
int32_t OEMReadAuthResultCode(char* buffer, uint32_t bufferLen)
{
    return ReadFile(AUTH_RESULT_PATH, AUTH_RESULT_CODE_FILE_NAME, buffer, bufferLen);
}
