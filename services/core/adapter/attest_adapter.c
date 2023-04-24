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
#include "device_attest_oem_adapter.h"

#include "attest_type.h"
#include "attest_utils_log.h"
#include "attest_adapter_oem.h"
#include "attest_adapter_os.h"
#include "attest_adapter_mock.h"
#include "attest_adapter.h"

// 是否存在重置标记
bool AttestIsResetFlagExist(void)
{
    return OEMIsResetFlagExist();
}
// 创建重置标记

int32_t AttestCreateResetFlag(void)
{
    return OEMCreateResetFlag();
}
// 写入认证结果
int32_t AttestWriteAuthStatus(const char* data, uint32_t len)
{
    return OEMWriteAuthStatus(data, len);
}

// 读取认证结果
int32_t AttestReadAuthStatus(char* buffer, uint32_t bufferLen)
{
    return OEMReadAuthStatus(buffer, bufferLen);
}

// 读取认证结果长度
int32_t AttestGetAuthStatusFileSize(uint32_t* len)
{
    return OEMGetAuthStatusFileSize(len);
}

// 读取凭据
int32_t AttestReadTicket(TicketInfo* ticketInfo)
{
    return OEMReadTicket(ticketInfo);
}

// 写入凭据
int32_t AttestWriteTicket(const TicketInfo* ticketInfo)
{
    return OEMWriteTicket(ticketInfo);
}

int32_t AttestSetParameter(const char *key, const char *value)
{
    return OsSetParameter(key, value);
}

int32_t AttestGetParameter(const char *key, const char *def, char *value, uint32_t len)
{
    return OsGetParameter(key, def, value, len);
}

int32_t AttestReadNetworkConfig(char* buffer, uint32_t bufferLen)
{
    return OEMReadNetworkConfig(buffer, bufferLen);
}

int32_t AttestWriteAuthResultCode(const char* data, uint32_t len)
{
    return OEMWriteAuthResultCode(data, len);
}

int32_t AttestReadAuthResultCode(char* buffer, uint32_t bufferLen)
{
    return OEMReadAuthResultCode(buffer, bufferLen);
}
