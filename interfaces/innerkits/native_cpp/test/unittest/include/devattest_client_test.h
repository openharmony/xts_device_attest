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

#ifndef DEVATTEST_CLIENT_TEST_H
#define DEVATTEST_CLIENT_TEST_H


#include <ipc_skeleton.h>
#include "devattest_test.h"

namespace OHOS {
namespace DevAttest {
class DevAttestClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

    int GetAttestStatusTest001(void);
    int GetAttestStatusProxyTest001(void);
    int GetAttestStatusProxyTest002(void);
    int GetAttestStatusProxyTest003(void);
    int GetAttestStatusProxyTest004(void);
    int GetAttestStatusProxyTest005(void);
} // namespace DevAttest
} // namespace OHOS
#endif // DEVATTEST_CLIENT_TEST_H
