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
    // GetXXX()会返回一段malloc内存,需手动释放
    char* manufacture = GetManufacture();
    if (manufacture == NULL) {
        return NULL;
    }
    char* res = AttestStrdup(manufacture);
    ATTEST_MEM_FREE(manufacture);
    return res;
}

char* OsGetProductModel(void)
{
    // GetXXX()会返回一段malloc内存,需手动释放
    char* productModel = GetProductModel();
    if (productModel == NULL) {
        return NULL;
    }
    char* res = AttestStrdup(productModel);
    ATTEST_MEM_FREE(productModel);
    return res;
}

char* OsGetBrand(void)
{
    return AttestStrdup(GetBrand());
}

char* OsGetSecurityPatchTag(void)
{
    return AttestStrdup(GetSecurityPatchTag());
}

char* OsGetSerial(void)
{
    return AttestStrdup(GetSerial());
}

char* OsGetUdid(void)
{
    char* udid = (char*)ATTEST_MEM_MALLOC(UDID_STRING_LEN + 1);
    if (udid == NULL) {
        return NULL;
    }
    (void)memset_s(udid, UDID_STRING_LEN + 1, 0, UDID_STRING_LEN + 1);
    int32_t ret = ATTEST_ERR;
    do {
        ret = GetDevUdid(udid, UDID_STRING_LEN + 1);
        if (ret != ATTEST_OK) {
            break;
        }
        ret = ToLowerStr(udid, UDID_STRING_LEN + 1);
        if (ret != ATTEST_OK) {
            break;
        }
    } while (0);
    if (ret != ATTEST_OK) {
        (void)memset_s(udid, UDID_STRING_LEN + 1, 0, UDID_STRING_LEN + 1);
        ATTEST_MEM_FREE(udid);
        return NULL;
    }
    char* outputStr = AttestStrdup(udid);
    (void)memset_s(udid, UDID_STRING_LEN + 1, 0, UDID_STRING_LEN + 1);
    ATTEST_MEM_FREE(udid);
    return outputStr;
}

int32_t OsSetParameter(const char *key, const char *value)
{
    return SetParameter(key, value);
}

int32_t OsGetParameter(const char *key, const char *def, char *value, uint32_t len)
{
    return GetParameter(key, def, value, len);
}