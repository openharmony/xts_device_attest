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

#ifndef ATTEST_ADAPTER_OS_H
#define ATTEST_ADAPTER_OS_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

char* OsGetVersionId(void);

char* OsGetBuildRootHash(void);

char* OsGetDisplayVersion(void);

char* OsGetManufacture(void);

char* OsGetProductModel(void);

char* OsGetBrand(void);

char* OsGetSecurityPatchTag(void);

char* OsGetUdid(void);

char* OsGetSerial(void);

int32_t OsSetParameter(const char *key, const char *value);

int32_t OsGetParameter(const char *key, const char *def, char *value, uint32_t len);


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif