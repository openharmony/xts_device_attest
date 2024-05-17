/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <stdio.h>
#include "attest_utils.h"
#include "attest_adapter_os.h"
#include "attest_tdd_mock_property.h"

char* AttestGetVersionId(void)
{
    return AttestStrdup(ATTEST_MOCK_PROPERTY_VERSIONID);
}

char* AttestGetBuildRootHash(void)
{
    return AttestStrdup(ATTEST_MOCK_PROPERTY_HASH);
}

char* AttestGetDisplayVersion(void)
{
    return AttestStrdup(ATTEST_MOCK_PROPERTY_SOFTWARE_VERSION);
}

char* AttestGetManufacture(void)
{
    return AttestStrdup(ATTEST_MOCK_PROPERTY_MANU);
}

char* AttestGetProductModel(void)
{
    return AttestStrdup(ATTEST_MOCK_PROPERTY_MODEL);
}

char* AttestGetBrand(void)
{
    return AttestStrdup(ATTEST_MOCK_PROPERTY_BRAND);
}

char* AttestGetSecurityPatchTag(void)
{
    return AttestStrdup(ATTEST_MOCK_PROPERTY_PATCH);
}

char* AttestGetUdid(void)
{
    return AttestStrdup(ATTEST_MOCK_PROPERTY_UDID);
}

char* AttestGetSerial(void)
{
    return AttestStrdup(ATTEST_MOCK_PROPERTY_SERIAL);
}
