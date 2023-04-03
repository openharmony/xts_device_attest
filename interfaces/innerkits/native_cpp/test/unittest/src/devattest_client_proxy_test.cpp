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

#include "devattest_client_test.h"

#include "devattest_client.h"
#include "devattest_service_proxy.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DevAttest;

namespace OHOS {
constexpr int ATTEST_SET_OPTION = 0;
constexpr int ATTEST_GET_OPTION = 1;
constexpr int ATTEST_TEST_ZERO_NUM = 0;
constexpr int ATTEST_TEST_FAILED_NUM1 = -3;
constexpr int ATTEST_TEST_FAILED_NUM2 = 1;
const std::string ATTEST_TEST_TICKET_STRING = "testTicket";

void ActionAttestResultInfo(int option, AttestResultInfo &attestResultInfo)
{
    static AttestResultInfo g_attestResultInfo;
    if (option == ATTEST_SET_OPTION) {
        g_attestResultInfo.authResult_ = attestResultInfo.authResult_;
        g_attestResultInfo.softwareResult_ = attestResultInfo.softwareResult_;
        for (int i = 0; i < SOFTWARE_RESULT_DETAIL_SIZE; i++) {
            g_attestResultInfo.softwareResultDetail_[i] = attestResultInfo.softwareResultDetail_[i];
        }
        g_attestResultInfo.ticketLength_ = attestResultInfo.ticketLength_;
        g_attestResultInfo.ticket_ = attestResultInfo.ticket_;
    } else {
        attestResultInfo.authResult_ = g_attestResultInfo.authResult_;
        attestResultInfo.softwareResult_ = g_attestResultInfo.softwareResult_;
        for (int i = 0; i < SOFTWARE_RESULT_DETAIL_SIZE; i++) {
            attestResultInfo.softwareResultDetail_[i] = g_attestResultInfo.softwareResultDetail_[i];
        }
        attestResultInfo.ticketLength_ = g_attestResultInfo.ticketLength_;
        attestResultInfo.ticket_ = g_attestResultInfo.ticket_;
    }
}

void SetAllAttestResultInfo(AttestResultInfo &attestResultInfo, int setNumber)
{
    attestResultInfo.authResult_ = setNumber;
    attestResultInfo.softwareResult_ = setNumber;
    for (int i = 0; i < SOFTWARE_RESULT_DETAIL_SIZE; i++) {
        attestResultInfo.softwareResultDetail_[i] = setNumber;
    }
}

int ActionReturnResult(int type, int option, int value)
{
    static int g_returnResult[ATTEST_TYPE_BUTT];
    if (type < ATTEST_TYPE_REPLY_RESULT || type >= ATTEST_TYPE_BUTT) {
        return DEVATTEST_FAIL;
    }

    if (option == ATTEST_SET_OPTION) {
        g_returnResult[type] = value;
    } else {
        return g_returnResult[type];
    }
    return DEVATTEST_SUCCESS;
}

class MockIRemoteObject : public IRemoteObject {
public:
    MockIRemoteObject() : IRemoteObject(u"mock_i_remote_object") {}

    ~MockIRemoteObject() {}

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.devattest.accessToken");

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        if (data.ReadInterfaceToken() != GetDescriptor()) {
            reply.WriteInt32(DEVATTEST_FAIL);
            return DEVATTEST_FAIL;
        }

        if (code < DevAttest::DevAttestInterface::GET_AUTH_RESULT ||
            code >= DevAttest::DevAttestInterface::ATTEST_INTERFACE_TYPE_BUTT) {
            return DEVATTEST_FAIL;
        }

        AttestResultInfo attestResultInfo;
        ActionAttestResultInfo(ATTEST_GET_OPTION, attestResultInfo);
        reply.WriteInt32(ActionReturnResult(ATTEST_TYPE_REPLY_RESULT, ATTEST_GET_OPTION, DEVATTEST_INIT));
        attestResultInfo.Marshalling(reply);
        return ActionReturnResult(ATTEST_TYPE_RETURN_RESULT, ATTEST_GET_OPTION, DEVATTEST_INIT);
    }

    bool IsProxyObject() const override
    {
        return true;
    }

    bool CheckObjectLegality() const override
    {
        return true;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }

    sptr<IRemoteBroker> AsInterface() override
    {
        return nullptr;
    }

    int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        return 0;
    }

    std::u16string GetObjectDescriptor() const
    {
        std::u16string descriptor = std::u16string();
        return descriptor;
    }
};
} // namespace OHOS

namespace OHOS {
namespace DevAttest {
void DevAttestClientTest::SetUpTestCase(void)
{
    // input testsuit setup step，setup invoked before all testcases
}

void DevAttestClientTest::TearDownTestCase(void)
{
    // input testsuit teardown step，teardown invoked after all testcases
}

void DevAttestClientTest::SetUp(void)
{
    // input testcase setup step，setup invoked before each testcases
    AttestResultInfo attestResultInfotemp;
    ActionAttestResultInfo(ATTEST_SET_OPTION, attestResultInfotemp);
    (void)ActionReturnResult(ATTEST_TYPE_REPLY_RESULT, ATTEST_SET_OPTION, DEVATTEST_SUCCESS);
    (void)ActionReturnResult(ATTEST_TYPE_RETURN_RESULT, ATTEST_SET_OPTION, DEVATTEST_SUCCESS);
}

void DevAttestClientTest::TearDown(void)
{
    // input testcase teardown step，teardown invoked after each testcases
}

/**
 * @tc.name: GetAttestStatusProxyTest001
 * @tc.desc: Test IPC interface returned failure.
 * @tc.type: FUNC
 * @tc.require: Issue I6RTOI
 */
HWTEST_F(DevAttestClientTest, GetAttestStatusProxyTest001, TestSize.Level1)
{
    sptr<IRemoteObject> object = new MockIRemoteObject();
    DevAttestServiceProxy devAttestServiceProxy(object);

    AttestResultInfo attestResultInfo;
    (void)ActionReturnResult(ATTEST_TYPE_RETURN_RESULT, ATTEST_SET_OPTION, DEVATTEST_FAIL);
    int ret = devAttestServiceProxy.GetAttestStatus(attestResultInfo);
    ASSERT_EQ(DEVATTEST_FAIL, ret);
}

/**
 * @tc.name: GetAttestStatusProxyTest002
 * @tc.desc: Test IPC interface returned success, but reply returned failure.
 * @tc.type: FUNC
 * @tc.require: Issue I6RTOI
 */
HWTEST_F(DevAttestClientTest, GetAttestStatusProxyTest002, TestSize.Level1)
{
    sptr<IRemoteObject> object = new MockIRemoteObject();
    DevAttestServiceProxy devAttestServiceProxy(object);

    AttestResultInfo attestResultInfo;
    (void)ActionReturnResult(ATTEST_TYPE_REPLY_RESULT, ATTEST_SET_OPTION, DEVATTEST_FAIL);
    int ret = devAttestServiceProxy.GetAttestStatus(attestResultInfo);
    EXPECT_EQ(DEVATTEST_FAIL, ret);

    (void)ActionReturnResult(ATTEST_TYPE_REPLY_RESULT, ATTEST_SET_OPTION, DEVATTEST_ERR_JS_IS_NOT_SYSTEM_APP);
    ret = devAttestServiceProxy.GetAttestStatus(attestResultInfo);
    ASSERT_EQ(DEVATTEST_ERR_JS_IS_NOT_SYSTEM_APP, ret);
}

/**
 * @tc.name: GetAttestStatusProxyTest003
 * @tc.desc: Test ticket of AttestResultInfo is empty, if other data is successful
 * @tc.type: FUNC
 * @tc.require: Issue I6RTOI
 */
HWTEST_F(DevAttestClientTest, GetAttestStatusProxyTest003, TestSize.Level1)
{
    AttestResultInfo attestResultInfotemp;
    SetAllAttestResultInfo(attestResultInfotemp, DEVATTEST_SUCCESS);
    attestResultInfotemp.ticketLength_ = ATTEST_TEST_TICKET_STRING.length();
    ActionAttestResultInfo(ATTEST_SET_OPTION, attestResultInfotemp);

    sptr<IRemoteObject> object = new MockIRemoteObject();
    DevAttestServiceProxy devAttestServiceProxy(object);

    AttestResultInfo attestResultInfo;
    int ret = devAttestServiceProxy.GetAttestStatus(attestResultInfo);
    EXPECT_EQ(ERR_OK, ret);
    ASSERT_FALSE(AttestStatusValid(attestResultInfo));
}

/**
 * @tc.name: GetAttestStatusTest001
 * @tc.desc: Test ticketLength of AttestResultInfo is zero, if other data is successful
 * @tc.type: FUNC
 * @tc.require: Issue I6RTOI
 */
HWTEST_F(DevAttestClientTest, GetAttestStatusProxyTest004, TestSize.Level1)
{
    AttestResultInfo attestResultInfotemp;
    SetAllAttestResultInfo(attestResultInfotemp, ATTEST_TEST_FAILED_NUM1);
    attestResultInfotemp.ticketLength_ = ATTEST_TEST_ZERO_NUM;
    attestResultInfotemp.ticket_ = ATTEST_TEST_TICKET_STRING;
    ActionAttestResultInfo(ATTEST_SET_OPTION, attestResultInfotemp);

    sptr<IRemoteObject> object = new MockIRemoteObject();
    DevAttestServiceProxy devAttestServiceProxy(object);

    AttestResultInfo attestResultInfo;
    int ret = devAttestServiceProxy.GetAttestStatus(attestResultInfo);
    EXPECT_EQ(ERR_OK, ret);
    ASSERT_FALSE(AttestStatusValid(attestResultInfo));
}

/**
 * @tc.name: GetAttestStatusProxyTest005
 * @tc.desc: Test authResult and softwareResult of AttestResultInfo is invaild, if other data is successful
 * @tc.type: FUNC
 * @tc.require: Issue I6RTOI
 */
HWTEST_F(DevAttestClientTest, GetAttestStatusProxyTest005, TestSize.Level1)
{
    AttestResultInfo attestResultInfotemp;
    SetAllAttestResultInfo(attestResultInfotemp, DEVATTEST_SUCCESS);
    attestResultInfotemp.authResult_ = ATTEST_TEST_FAILED_NUM1;
    attestResultInfotemp.softwareResult_ = ATTEST_TEST_FAILED_NUM2;
    attestResultInfotemp.ticketLength_ = ATTEST_TEST_TICKET_STRING.length();
    attestResultInfotemp.ticket_ = ATTEST_TEST_TICKET_STRING;

    ActionAttestResultInfo(ATTEST_SET_OPTION, attestResultInfotemp);

    sptr<IRemoteObject> object = new MockIRemoteObject();
    DevAttestServiceProxy devAttestServiceProxy(object);

    AttestResultInfo attestResultInfo;
    int ret = devAttestServiceProxy.GetAttestStatus(attestResultInfo);
    EXPECT_EQ(ERR_OK, ret);
    ASSERT_FALSE(AttestStatusValid(attestResultInfo));
}
} // namespace DevAttest
} // namespace OHOS
