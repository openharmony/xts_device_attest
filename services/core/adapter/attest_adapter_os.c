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

#include "parameter.h"
#include "attest_type.h"
#include "attest_utils.h"
#include "attest_adapter_os.h"

char* OsGetVersionId(void)
{
    return AttestStrdup(GetVersionId());
}

char* OsGetBuildRootHash(void)
{
    return AttestStrdup(GetBuildRootHash());
}

char* OsGetDisplayVersion(void)
{
    return AttestStrdup(GetDisplayVersion());
}

char* OsGetManufacture(void)
{
    return AttestStrdup(GetManufacture());
}

char* OsGetProductModel(void)
{
    return AttestStrdup(GetProductModel());
}

char* OsGetBrand(void)
{
    return AttestStrdup(GetBrand());
}

char* OsGetSecurityPatchTag(void)
{
    return AttestStrdup(GetSecurityPatchTag());
}

char* OsGetUdid(void)
{
    char udid[UDID_STRING_LEN + 1] = {0};
    if (memset_s(udid, sizeof(udid), 0, sizeof(udid)) != 0) {
        return NULL;
    }
    char *devUdid = udid;
    int32_t ret = GetDevUdid(devUdid, sizeof(udid));
    if (ret != ATTEST_OK) {
        return NULL;
    }
    return AttestStrdup(devUdid);
}

int32_t OsSetParameter(const char *key, const char *value)
{
    return SetParameter(key, value);
}

int32_t OsGetParameter(const char *key, const char *def, char *value, uint32_t len)
{
    return GetParameter(key, def, value, len);
}