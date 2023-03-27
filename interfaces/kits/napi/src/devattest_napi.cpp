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
#include <string>
#include "devattest_log.h"
#include "devattest_errno.h"
#include "devattest_client.h"
#include "attest_result_info.h"
#include "devattest_napi.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::DevAttest;

struct DevAttestAsyncContext {
    napi_async_work work;
    napi_ref callbackRef = nullptr; // 用于callback模式
    napi_deferred deferred; // 用于promise模式
    AttestResultInfo value; // 返回值
    int32_t ret = DEVATTEST_ERR_JS_SYSTEM_SERVICE_EXCEPTION;
};

static napi_value GenerateDevAttestHandle(napi_env env, int32_t auth, int32_t software, string ticketStr,
    vector<int32_t> &softwareDetail)
{
    napi_value resultObject;
    napi_create_object(env, &resultObject);
    napi_value authResult;
    napi_value softwareResult;
    napi_value ticket;
    
    napi_create_int32(env, auth, &authResult);
    napi_create_int32(env, software, &softwareResult);
    napi_create_string_utf8(env, ticketStr.c_str(), ticketStr.length(), &ticket);
    napi_set_named_property(env, resultObject, "authResult", authResult);
    napi_set_named_property(env, resultObject, "softwareResult", softwareResult);
    napi_set_named_property(env, resultObject, "ticket", ticket);

    napi_value softwareResultDetail;
    napi_create_array(env, &softwareResultDetail);
    size_t index = 0;
    for (auto& vecData : softwareDetail) {
        napi_value id;
        napi_create_int32(env, vecData, &id);
        napi_set_element(env, softwareResultDetail, index, id);
        index++;
    }
    napi_set_named_property(env, resultObject, "softwareResultDetail", softwareResultDetail);
    return resultObject;
}

static napi_value GenerateBusinessError(napi_env env, int32_t code)
{
    napi_value result;
    int32_t jsErrCode = ConvertToJsErrCode(code);
    HILOGI("[GenerateBusinessError] jsErrCode:%{public}d", jsErrCode);
    if (jsErrCode == DEVATTEST_SUCCESS) {
        napi_get_undefined(env, &result);
    } else {
        napi_value errCode = nullptr;
        napi_create_int32(env, jsErrCode, &errCode);

        string errMsgStr = ConvertToJsErrMsg(jsErrCode);
        napi_value errMsg = nullptr;
        napi_create_string_utf8(env, errMsgStr.c_str(), NAPI_AUTO_LENGTH, &errMsg);
        
        napi_create_error(env, nullptr, errMsg, &result);
        napi_set_named_property(env, result, "code", errCode);
    }
    return result;
}

static napi_value GenerateReturnValue(napi_env env, DevAttestAsyncContext* callback)
{
    napi_value result;
    if (callback->ret == DEVATTEST_SUCCESS) {
        result = GenerateDevAttestHandle(env, callback->value.authResult_, callback->value.softwareResult_,
            callback->value.ticket_, callback->value.softwareResultDetail_);
    } else {
        napi_get_undefined(env, &result);
    }
    return result;
}

/* 耗时操作 */
static void Execute(napi_env env, void* data)
{
    if (data == nullptr) {
        HILOGI("[Execute] Invalid parameter");
        return;
    }
    DevAttestAsyncContext *asyncContext = static_cast<DevAttestAsyncContext*>(data);
    int32_t ret = DelayedSingleton<DevAttestClient>::GetInstance()->GetAttestStatus(asyncContext->value);
    if (ret == DEVATTEST_FAIL) {
        asyncContext->ret = DEVATTEST_ERR_JS_SYSTEM_SERVICE_EXCEPTION;
    } else {
        asyncContext->ret = ret;
    }
}

/* 传参，不耗时 */
static void Complete(napi_env env, napi_status status, void* data)
{
    DevAttestAsyncContext* callback = static_cast<DevAttestAsyncContext*>(data);

    // 根据Execute函数的结果进行返回值的赋值, result[0]存放error; result[1]存放返回值
    napi_value result[2] = {0};
    result[0] = GenerateBusinessError(env, callback->ret);
    result[1] = GenerateReturnValue(env, callback);

    if (callback->callbackRef != nullptr) { // callback模式
        // 调用对应的js的callback函数
        napi_value callbackfunc = nullptr;
        napi_get_reference_value(env, callback->callbackRef, &callbackfunc);
        napi_value returnValue;
        // 此函数的最后一个参数不可传nullptr，否则程序会崩溃
        napi_call_function(env, nullptr, callbackfunc, sizeof(result) / sizeof(result[0]), result, &returnValue);
        napi_delete_reference(env, callback->callbackRef);
    } else { // promise模式
        if (callback->ret == DEVATTEST_SUCCESS) {
            napi_resolve_deferred(env, callback->deferred, result[1]);
        } else {
            napi_reject_deferred(env, callback->deferred, result[0]);
        }
    }
    napi_delete_async_work(env, callback->work); // 异步任务完成之后删除任务
    delete callback;
}

/* [js] getAttestStatus(callback: AsyncCallback<AttestResultInfo>) : void */
/* [js] getAttestStatus() : Promise<AttestResultInfo> */
napi_value DevAttestNapi::GetAttestResultInfo(napi_env env, napi_callback_info info)
{
    // 获取js的入参数据
    size_t argc = PARAM1; // 参数个数
    napi_value argv[1] = {0}; // 参数的值
    napi_value thisVar = nullptr; // js对象的this指针
    void* data = nullptr; // 回调数据指针
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc > PARAM1) {
        HILOGE("[GetAttestResultInfo] Input at most 1 paramter");
        napi_throw(env, GenerateBusinessError(env, DEVATTEST_ERR_JS_PARAMETER_ERROR));
    }

    // 判断入参的类型是否正确
    napi_valuetype type = napi_undefined;
    if (argc == PARAM1) {
        napi_typeof(env, argv[0], &type);
        if (type != napi_function) {
            HILOGE("[GetAttestResultInfo] the type of argv[0] is not function");
            napi_throw(env, GenerateBusinessError(env, DEVATTEST_ERR_JS_PARAMETER_ERROR));
        }
    }

    std::unique_ptr<DevAttestAsyncContext> callback = std::make_unique<DevAttestAsyncContext>();

   // 解析入参callback,判断callback
    if (argc == PARAM1) {
        napi_create_reference(env, argv[0], 1, &callback->callbackRef);
    }

    // 判断模式,callback ref为空，说明是promise模式，反之是callback模式
    napi_value promise = nullptr;
    if (!callback->callbackRef) {
        napi_create_promise(env, &callback->deferred, &promise);
    } else {
        napi_get_undefined(env, &promise);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetAttestResultInfo", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env, nullptr, resource,
        Execute,
        Complete,
        static_cast<void*>(callback.get()),
        &callback->work);
    napi_queue_async_work(env, callback->work);
    callback.release();
    return promise;
}

/* [js] getAttestStatusSync() : AttestResultInfo */
napi_value DevAttestNapi::GetAttestResultInfoSync(napi_env env, napi_callback_info info)
{
    AttestResultInfo attestResultInfo;
    int32_t errCode = DelayedSingleton<DevAttestClient>::GetInstance()->GetAttestStatus(attestResultInfo);
    if (errCode != DEVATTEST_SUCCESS) {
        HILOGE("[GetAttestResultInfoSync] GetAttestStatus failed errCode:%{public}d", errCode);
        napi_throw(env, GenerateBusinessError(env, errCode));
    }

    return GenerateDevAttestHandle(env, attestResultInfo.authResult_, attestResultInfo.softwareResult_,
        attestResultInfo.ticket_, attestResultInfo.softwareResultDetail_);
}

napi_value DevAttestNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("getAttestStatus", GetAttestResultInfo),
        DECLARE_NAPI_STATIC_FUNCTION("getAttestStatusSync", GetAttestResultInfoSync)
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

EXTERN_C_START
static napi_value DevattestInit(napi_env env, napi_value exports)
{
    HILOGI("Initialize the DevAttestNapi module");
    napi_value ret = DevAttestNapi::Init(env, exports);
    HILOGI("The initialization of the DevAttestNapi module is complete");
    return ret;
}
EXTERN_C_END

static napi_module _module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = DevattestInit,
    .nm_modname = "deviceAttest",
    .nm_priv = ((void *)0),
    .reserved = { 0 }
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&_module);
}
