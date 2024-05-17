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
#include "attest_adapter_mock.h"
#include "attest_adapter_os.h"
#include "attest_adapter.h"

char* AttestGetVersionId(void)
{
    if (ATTEST_MOCK_DEVICE_STUB_FLAG) {
        return OsGetVersionIdStub();
    }
    return OsGetVersionId();
}

char* AttestGetBuildRootHash(void)
{
    if (ATTEST_MOCK_DEVICE_STUB_FLAG) {
        return OsGetBuildRootHashStub();
    }
    return OsGetBuildRootHash();
}

char* AttestGetDisplayVersion(void)
{
    if (ATTEST_MOCK_DEVICE_STUB_FLAG) {
        return OsGetDisplayVersionStub();
    }
    return OsGetDisplayVersion();
}

char* AttestGetManufacture(void)
{
    if (ATTEST_MOCK_DEVICE_STUB_FLAG) {
        return OsGetManufactureStub();
    }
    return OsGetManufacture();
}

char* AttestGetProductModel(void)
{
    if (ATTEST_MOCK_DEVICE_STUB_FLAG) {
        return OsGetProductModelStub();
    }
    return OsGetProductModel();
}

char* AttestGetBrand(void)
{
    if (ATTEST_MOCK_DEVICE_STUB_FLAG) {
        return OsGetBrandStub();
    }
    return OsGetBrand();
}

char* AttestGetSecurityPatchTag(void)
{
    if (ATTEST_MOCK_DEVICE_STUB_FLAG) {
        return OsGetSecurityPatchTagStub();
    }
    return OsGetSecurityPatchTag();
}

char* AttestGetUdid(void)
{
    if (ATTEST_MOCK_DEVICE_STUB_FLAG) {
        return OsGetUdidStub();
    }
    return OsGetUdid();
}

char* AttestGetSerial(void)
{
    if (ATTEST_MOCK_DEVICE_STUB_FLAG) {
        return OsGetSerialStub();
    }
    return OsGetSerial();
}
