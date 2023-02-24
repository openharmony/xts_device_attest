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

#ifndef __ATTEST_NETWORK_H__
#define __ATTEST_NETWORK_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifdef __ATTEST_NETWORK_DEBUG_LOG__
#define ATTEST_NETWORK_DEBUG_LOG_FLAG true
#else
#define ATTEST_NETWORK_DEBUG_LOG_FLAG false
#endif

#define SSL_OK       1
#define SSL_ERR      0

#define HTTP_OK      200

#define HTTPS_NETWORK_PORT "443"
#define HTTPS_NETWORK_HEADER_MAXLEN 512     // Headers的最大长度
#define HTTPS_NETWORK_RESPONSE_MAXLEN 2048  // Response返回值的最大长度
#define HTTPS_NETWORK_SHA256_LEN 128
#define HTTPS_NETWORK_BUFFER_LEN (1024 * 240)

typedef struct HttpPacketStruct {
    char *reqPort;
    char *reqHost;
    char *reqMethod;
    char *reqXclientID;
    char *reqXtraceID;
    char *reqXappID;
    char *reqXtenantID;
    int32_t reqContentLength;
} HttpPacket;

typedef enum {
    ATTEST_HTTPS_RESCODE = 0,
    ATTEST_HTTPS_RESTYPE,
    ATTEST_HTTPS_RESLEN,
    ATTEST_HTTPS_BLANK,
    ATTEST_HTTPS_MAX,
} ATTEST_HTTPHEAD_TYPE;

#define HTTPS_POST_FORMAT ("POST %s HTTP/1.0\r\n\
Host: %s:%s\r\n\
x-clientid: %s\r\n\
x-traceId: %s\r\n\
x-appid: %s\r\n\
x-tenantid: %s\r\n\
Content-type: application/json\r\n\
Content-Length: %d\r\n\r\n")


#define FILL_HTTPS_POST_FORMAT_ARGS(httpPacket) \
    (httpPacket).reqMethod, (httpPacket).reqHost, (httpPacket).reqPort, \
    (httpPacket).reqXclientID, (httpPacket).reqXtraceID, \
    (httpPacket).reqXappID, (httpPacket).reqXtenantID, (httpPacket).reqContentLength

DevicePacket* CreateDevicePacket(void);

void DestroyDevicePacket(DevicePacket** devicePacket);

#define FREE_DEVICE_PACKET(devicePacket) DestroyDevicePacket((DevicePacket**)&(devicePacket))

int32_t SendAttestMsg(DevicePacket *devValue, ATTEST_ACTION_TYPE actionType, char **respBodyData);

typedef char* (*BuildBodyFunc)(DevicePacket *);

char* BuildHttpsChallBody(DevicePacket *devPacket);

char* BuildHttpsResetBody(DevicePacket *devPacket);

char* BuildHttpsAuthBody(DevicePacket *devPacket);

char* BuildHttpsActiveBody(DevicePacket *devPacket);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif