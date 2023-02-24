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

#ifndef __ATTEST_SERVICE_DEVICE_H__
#define __ATTEST_SERVICE_DEVICE_H__

#include "attest_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

typedef enum {
    VERSION_ID = 0,
    ROOT_HASH,
    DISPLAY_VERSION,
    MANU_FACTURE,
    PRODUCT_MODEL,
    BRAND,
    SECURITY_PATCH_TAG,
    UDID,
    RANDOM_UUID,
    APP_ID,
    TENANT_ID,
    PCID,
    SYS_DEV_MAX, // 注意: 添加枚举值需要同步修改 g_devSysInfos 和 g_devSysInfosStr
} SYS_DEV_TYPE_E;

typedef enum {
    FIRST_CASE = 1,
    SECOND_CASE = 2,
    THIRD_CASE = 3,
    FOURTH_CASE = 4,
} SYS_DEV_CASE_TYPE;

typedef char* (*SetDataFunc)(void);

int32_t InitSysData(void);

void DestroySysData(void);

char* StrdupDevInfo(SYS_DEV_TYPE_E devType);

char* GetRandomUuid(void);

char* GetAppId(void);

char* GetTenantId(void);

char* GetPcid(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif

