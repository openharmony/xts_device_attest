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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "openssl/ssl.h"
#include "openssl/crypto.h"
#include "openssl/rand.h"
#include "openssl/err.h"
#include "openssl/sha.h"

#include "cJSON.h"
#include "securec.h"

#include "attest_utils_log.h"
#include "attest_utils_list.h"
#include "attest_utils.h"
#include "attest_type.h"
#include "attest_adapter.h"
#include "attest_network.h"

#ifdef __cplusplus
#if __cplusplus
    extern "C" {
#endif
#endif

List g_attestNetworkList;

char *g_httpHeaderName[ATTEST_HTTPS_MAX] = {
    "HTTP/1.1",
    "Content-Type:",
    "Content-Length:",
    ""
};
BuildBodyFunc g_buildBodyFunc[ATTEST_ACTION_MAX] = {
    BuildHttpsChallBody,
    BuildHttpsResetBody,
    BuildHttpsAuthBody,
    BuildHttpsActiveBody,
};
char *g_uriPath[ATTEST_ACTION_MAX] = {
    "/wisedevice/device-policy/v3/challenge",
    "/wisedevice/device-policy/v3/reset",
    "/wisedevice/device-policy/v3/auth",
    "/wisedevice/device-policy/v3/token/activate",
};

DevicePacket* CreateDevicePacket(void)
{
    DevicePacket* devicePacket = (DevicePacket *)ATTEST_MEM_MALLOC(sizeof(DevicePacket));
    if (devicePacket == NULL) {
        ATTEST_LOG_ERROR("[CreateDevicePacket] devicePacket malloc memory failed");
        return NULL;
    }
    devicePacket->appId = NULL;
    devicePacket->tenantId = NULL;
    devicePacket->udid = NULL;
    devicePacket->ticket = NULL;
    devicePacket->randomUuid = NULL;
    devicePacket->tokenInfo.uuid = NULL;
    devicePacket->tokenInfo.token = NULL;
    devicePacket->productInfo.prodId = NULL;
    devicePacket->productInfo.model = NULL;
    devicePacket->productInfo.brand = NULL;
    devicePacket->productInfo.manu = NULL;
    devicePacket->productInfo.versionId = NULL;
    devicePacket->productInfo.displayVersion = NULL;
    devicePacket->productInfo.rootHash = NULL;
    devicePacket->productInfo.patchTag = NULL;
    devicePacket->kitinfo = NULL;
    devicePacket->pcid = NULL;
    return devicePacket;
}

void DestroyDevicePacket(DevicePacket** devPacket)
{
    if (devPacket == NULL || *devPacket == NULL) {
        ATTEST_LOG_ERROR("[DestroyDevicePacket] Invalid parameter");
        return;
    }
    DevicePacket* devicePacket = *devPacket;
    ATTEST_MEM_FREE(devicePacket->appId);
    ATTEST_MEM_FREE(devicePacket->tenantId);
    ATTEST_MEM_FREE(devicePacket->udid);
    ATTEST_MEM_FREE(devicePacket->ticket);
    ATTEST_MEM_FREE(devicePacket->randomUuid);
    ATTEST_MEM_FREE(devicePacket->tokenInfo.uuid);
    ATTEST_MEM_FREE(devicePacket->tokenInfo.token);
    ATTEST_MEM_FREE(devicePacket->productInfo.prodId);
    ATTEST_MEM_FREE(devicePacket->productInfo.model);
    ATTEST_MEM_FREE(devicePacket->productInfo.brand);
    ATTEST_MEM_FREE(devicePacket->productInfo.manu);
    ATTEST_MEM_FREE(devicePacket->productInfo.versionId);
    ATTEST_MEM_FREE(devicePacket->productInfo.displayVersion);
    ATTEST_MEM_FREE(devicePacket->productInfo.rootHash);
    ATTEST_MEM_FREE(devicePacket->productInfo.patchTag);
    ATTEST_MEM_FREE(devicePacket->kitinfo);
    ATTEST_MEM_FREE(devicePacket->pcid);
    ATTEST_MEM_FREE(*devPacket);
}

static int32_t Sha256Udid(char *udid, char *outStr)
{
    unsigned char hash[HTTPS_NETWORK_SHA256_LEN];
    SHA256_CTX sha256;
    if (udid == NULL || outStr == NULL) {
        ATTEST_LOG_ERROR("[Sha256Udid] Invalid parameter");
        return -1;
    }
    
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, udid, strlen(udid));
    SHA256_Final(hash, &sha256);
    
    uint32_t curLen = 0;
    for (uint32_t i = 0; i < strlen((char *)hash); i++) {
        if (curLen > (HTTPS_NETWORK_SHA256_LEN - 1)) {
            ATTEST_LOG_ERROR("[Sha256Udid] CurLen(%d) is more than maxLen(%d).", curLen, HTTPS_NETWORK_SHA256_LEN);
            return ATTEST_OK;
        }
        curLen += snprintf_s((char *)&outStr[i << 1], (uint32_t)(HTTPS_NETWORK_SHA256_LEN - curLen),
            (uint32_t)(HTTPS_NETWORK_SHA256_LEN - curLen) - 1, "%02x", hash[i]);
    }

    ATTEST_LOG_DEBUG_ANONY("[Sha256Udid] udid = %s", udid);
    ATTEST_LOG_DEBUG_ANONY("[Sha256Udid] SHA(udid)=%s", outStr);
    return ATTEST_OK;
}

static int32_t SetSocketCliented(char* udid, char **outClientId)
{
    if (outClientId == NULL) {
        ATTEST_LOG_ERROR("[SetSocketCliented] Invalid parameter");
        return ATTEST_ERR;
    }

    // OpenHarmony设备是大写Udid，云端计算clientId是用小写Udid，适配下
    int32_t retCode = ToLowerStr(udid, UDID_STRING_LEN);
    if (retCode != ATTEST_OK) {
        return ATTEST_ERR;
    }

    char *clientId = (char *)ATTEST_MEM_MALLOC(HTTPS_NETWORK_SHA256_LEN);
    if (clientId == NULL) {
        ATTEST_LOG_ERROR("[SetSocketCliented] clientId ATTEST MEM MALLOC failed");
        return ATTEST_ERR;
    }
    retCode = Sha256Udid(udid, clientId);
    if (retCode != ATTEST_OK) {
        ATTEST_LOG_ERROR("[SetSocketCliented] SHA256 uid fail, ret = %d.\n", retCode);
        ATTEST_MEM_FREE(clientId);
        return ATTEST_ERR;
    }
    *outClientId = clientId;
    return ATTEST_OK;
}

static int32_t SetSocketTracekId(char *clientId, char* randomUuid, char **outTracekId)
{
    int clientIdLastLen = 10; // clientid后10位;
    if (clientId == NULL || randomUuid == NULL || outTracekId == NULL) {
        ATTEST_LOG_ERROR("[SetSocketTracekId] Invalid parameter");
        return ATTEST_ERR;
    }
    
    int32_t traceIdLen = strlen(randomUuid) + clientIdLastLen + 2; // traceid拼写规则:clientId后10位+'_'+randomUuid+'\0'(2字符)
    char *tracekId = (char *)ATTEST_MEM_MALLOC(traceIdLen);
    if (tracekId == NULL) {
        ATTEST_LOG_ERROR("[SetSocketTracekId] tracekId ATTEST MEM MALLOC failed");
        return ATTEST_ERR;
    }
    
    int32_t retCode = memcpy_s(tracekId, traceIdLen, clientId + strlen(clientId) - clientIdLastLen, clientIdLastLen);
    if (retCode != ATTEST_OK) {
        ATTEST_MEM_FREE(tracekId);
        ATTEST_LOG_ERROR("[SetSocketTracekId] memcpy_s tracekId failed");
        return ATTEST_ERR;
    }

    retCode = sprintf_s(tracekId, traceIdLen, "%s_%s", tracekId, randomUuid);
    if (retCode < 0) {
        ATTEST_MEM_FREE(tracekId);
        ATTEST_LOG_ERROR("[SetSocketTracekId] sprintf_s tracekId failed");
        return ATTEST_ERR;
    }
    *outTracekId = tracekId;
    return ATTEST_OK;
}

static int32_t BuildSocketInfo(DevicePacket *devValue, HttpPacket *msgHttpPack,
    int32_t actionType, int32_t reqContentLength)
{
    ATTEST_LOG_DEBUG("[BuildSocketInfo] Begin.");
    if (msgHttpPack == NULL || devValue == NULL || g_attestNetworkList.head == NULL) {
        ATTEST_LOG_ERROR("[BuildSocketInfo] Invalid parameter");
        return ATTEST_ERR;
    }

    ServerInfo* serverInfo = (ServerInfo*)g_attestNetworkList.head->data;

    msgHttpPack->reqPort = serverInfo->port;
    msgHttpPack->reqHost = serverInfo->hostName;
    msgHttpPack->reqMethod = g_uriPath[actionType];
    msgHttpPack->reqXappID = devValue->appId;
    msgHttpPack->reqXtenantID = devValue->tenantId;
    msgHttpPack->reqContentLength = reqContentLength;

    char *reqXclientID = NULL;
    int32_t retCode = SetSocketCliented(devValue->udid, &reqXclientID);
    if (retCode != ATTEST_OK) {
        ATTEST_LOG_ERROR("[BuildSocketInfo] Set Socket Cliented failed");
        return ATTEST_ERR;
    }

    char *reqXtraceID = NULL;
    retCode = SetSocketTracekId(reqXclientID, devValue->randomUuid, &reqXtraceID);
    if (retCode != ATTEST_OK) {
        ATTEST_MEM_FREE(reqXclientID);
        ATTEST_LOG_ERROR("[BuildSocketInfo] Set Socket TracekId failed");
        return ATTEST_ERR;
    }
    msgHttpPack->reqXclientID = reqXclientID;
    msgHttpPack->reqXtraceID = reqXtraceID;
    ATTEST_LOG_DEBUG("[BuildSocketInfo] End.");
    return ATTEST_OK;
}

static int32_t InitAddrInfo(struct addrinfo **resAddr)
{
    if (resAddr == NULL || g_attestNetworkList.head == NULL) {
        ATTEST_LOG_ERROR("[InitAddrInfo] Invalid parameter");
        return ATTEST_ERR;
    }

    struct addrinfo hints;
    struct addrinfo *returnAddr = NULL;

    if (memset_s(&hints, sizeof(struct addrinfo), 0, sizeof(struct addrinfo)) != ATTEST_OK) {
        ATTEST_LOG_ERROR("[InitAddrInfo] Init template hints failed");
        return ATTEST_ERR;
    }

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_IP;

    ServerInfo* serverInfo = (ServerInfo*)g_attestNetworkList.head->data;

    if (getaddrinfo(serverInfo->hostName, serverInfo->port, &hints, &returnAddr) != ATTEST_OK) {
        ATTEST_LOG_ERROR("[InitAddrInfo] InitSocket getaddr fail, error:%d", h_errno);
        return ATTEST_ERR;
    }
    *resAddr = returnAddr;
    return ATTEST_OK;
}

static int32_t InitSocketClientImpl(struct addrinfo *resAddr, int32_t *socketFd)
{
    if (resAddr == NULL || socketFd == NULL) {
        ATTEST_LOG_ERROR("[InitSocketClientImpl] InitSocket Parameter is NULL");
        return ATTEST_ERR;
    }

    int32_t ret = ATTEST_OK;
    int32_t sockfd = 0;
    for (struct addrinfo *curAddr = resAddr; curAddr != NULL; curAddr = curAddr->ai_next) {
        sockfd = (int)socket(curAddr->ai_family, curAddr->ai_socktype, IPPROTO_IP);
        if (sockfd < 0) {
            ret = ATTEST_ERR;
            continue;
        }

        if (connect(sockfd, curAddr->ai_addr, curAddr->ai_addrlen) == 0) {
            ret = ATTEST_OK;
            break;
        }

        close(sockfd);
        ret = ATTEST_ERR;
    }
    if (ret != ATTEST_OK) {
        return ATTEST_ERR;
    }
    *socketFd = sockfd;
    return ATTEST_OK;
}

static int32_t InitSocketClient(int32_t *socketFd)
{
    if (socketFd == NULL) {
        ATTEST_LOG_ERROR("[InitSocketClient] InitSocket Parameter is NULL");
        return ATTEST_ERR;
    }

    int32_t sockfd = 0;
    int32_t bufLen = HTTPS_NETWORK_BUFFER_LEN;
    struct timeval timeout = {60, 0};
    struct addrinfo *resAddr = NULL;

    int32_t ret = InitAddrInfo(&resAddr);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[InitSocketClient] InitAddrInfo fail");
        return ATTEST_ERR;
    }

    ret = InitSocketClientImpl(resAddr, &sockfd);
    freeaddrinfo(resAddr);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[InitSocketClient] InitSocket connect fail");
        return ATTEST_ERR;
    }

    /* 设置socket连接的一些属性，超时时间，发送缓冲区Buffer等 */
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout)) < 0) {
        ATTEST_LOG_ERROR("[InitSocketClient] Setsockopt send timeout fail");
        return ATTEST_ERR;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char *)&bufLen, 4) < 0) {
        ATTEST_LOG_ERROR("[InitSocketClient] Setsockopt sendbuffer fail");
        return ATTEST_ERR;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) < 0) {
        ATTEST_LOG_ERROR("[InitSocketClient] Setsockopt rcv fail");
        return ATTEST_ERR;
    }

    *socketFd = sockfd;
    return ATTEST_OK;
}

static int32_t InitSSLSocket(int32_t socketFd, SSL **socketSSL)
{
    int32_t retCode;
    char *caFile = "/etc/ssl/certs/cacert.pem";

    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    SSL_CTX *socketCTX = SSL_CTX_new(SSLv23_client_method());
    if (socketCTX == NULL) {
        ATTEST_LOG_ERROR("[InitSSLSocket] SSL CTX create failed");
        return ATTEST_ERR;
    }

    do {
        /* 设置根证书检验 */
        SSL_CTX_set_verify(socketCTX, SSL_VERIFY_PEER, NULL);
        retCode = SSL_CTX_load_verify_locations(socketCTX, caFile, NULL);
        if (retCode != SSL_OK) {
            ATTEST_LOG_ERROR("[InitSSLSocket] InitSSL load_verify fail \n");
            break;
        }
        /* 设置和服务器端进行协商的算法套件 */
        SSL_CTX_set_cipher_list(socketCTX, "ALL:!EXP");
        SSL_CTX_set_mode(socketCTX, SSL_MODE_AUTO_RETRY);
        *socketSSL = SSL_new(socketCTX);
        if (*socketSSL == NULL) {
            break;
        }
    } while (0);
    SSL_CTX_free(socketCTX);

    retCode = SSL_set_fd(*socketSSL, socketFd);
    if (retCode != SSL_OK) {
        ATTEST_LOG_ERROR("[InitSSLSocket] InitSSL SSL_set_fd fail, retCode=%d \n", retCode);
        return ATTEST_ERR;
    }

    retCode = SSL_connect(*socketSSL);
    if (retCode != SSL_OK) {
        ATTEST_LOG_ERROR("[InitSSLSocket] InitSSL SSL_connect fail, retCode=%d \n", retCode);
        return ATTEST_ERR;
    }

    return ATTEST_OK;
}

static int32_t SendSSL(SSL *socketSSL, char *postData, int32_t postDataLen)
{
    int32_t sendCnt = 0;

    while (sendCnt < postDataLen) {
        int32_t writeCnt = SSL_write(socketSSL, postData + sendCnt, postDataLen - sendCnt);
        int32_t retCode = SSL_get_error(socketSSL, writeCnt);
        if (retCode == SSL_ERROR_NONE) {
            if (writeCnt > 0) {
                sendCnt += writeCnt;
                continue;
            } else {
                ATTEST_LOG_ERROR("[SendSSL] SendSSL fail, writeCnt=%d \n", writeCnt);
            }
        } else if (retCode == SSL_ERROR_WANT_READ) {
            continue;
        } else if (retCode == SSL_ERROR_WANT_WRITE) {
            continue;
        } else {
            ATTEST_LOG_ERROR("[SendSSL] SendSSL fail, retCode=%d \n", retCode);
            break;
        }
    }
    return sendCnt;
}

static int32_t RecvSSL(SSL *socketSSL, char **outMsg)
{
    char *respData = (char*)ATTEST_MEM_MALLOC(HTTPS_NETWORK_RESPONSE_MAXLEN);
    if (respData == NULL) {
        ATTEST_LOG_ERROR("[RecvSSL] respData ATTEST MEM MALLOC failed");
        return ATTEST_ERR;
    }
    int32_t readCnt = SSL_read(socketSSL, respData, HTTPS_NETWORK_RESPONSE_MAXLEN);
    int32_t retCode = SSL_get_error(socketSSL, readCnt);
   /* resData的内存申请门限是大于实际读取的值，如果超过说明数据己不准确 */
    if ((retCode == SSL_ERROR_NONE) && (readCnt < HTTPS_NETWORK_RESPONSE_MAXLEN)) {
        *outMsg = respData;
        return ATTEST_OK;
    }

    ATTEST_LOG_ERROR("[RecvSSL]RecvSSL fail, retCode=%d \n", retCode);
    ATTEST_MEM_FREE(respData);
    return ATTEST_ERR;
}

static int32_t VerifySSLCA(SSL *postSSL)
{
    int32_t retCode;
    char *outputCert = NULL;
    X509 *srvCert = NULL;

    retCode = SSL_get_verify_result(postSSL);
    if (retCode != X509_V_OK) {
        ATTEST_LOG_ERROR("[VerifySSLCA] VerifySSLCA X509 fail, retCode=%d\n%s\n", retCode, \
            X509_verify_cert_error_string(retCode));
        return ATTEST_ERR;
    }

    srvCert = SSL_get_peer_certificate(postSSL);
    if (srvCert == NULL) {
        ATTEST_LOG_ERROR("[VerifySSLCA] VerifySSLCA get cert X509 fail");
        return ATTEST_ERR;
    }

    outputCert = X509_NAME_oneline(X509_get_subject_name(srvCert), 0, 0);
    free(outputCert);

    outputCert = X509_NAME_oneline(X509_get_issuer_name(srvCert), 0, 0);
    free(outputCert);

    X509_free(srvCert);

    return ATTEST_OK;
}

static int32_t BuildHttpsHead(DevicePacket *devValue, int32_t reqBodyLen, ATTEST_ACTION_TYPE action, char **headData)
{
    ATTEST_LOG_DEBUG("[BuildHttpsHead] Begin.");
    /* 获取网络基础数据 */
    HttpPacket msgHttpPack;
    int32_t retCode = BuildSocketInfo(devValue, &msgHttpPack, action, reqBodyLen);
    if (retCode != ATTEST_OK) {
        ATTEST_LOG_ERROR("[BuildHttpsHead] Build Socket Info fail");
        return ATTEST_ERR;
    }

    int32_t headerMaxLen = HTTPS_NETWORK_HEADER_MAXLEN;
    char *reqHeadData = (char *)ATTEST_MEM_MALLOC(headerMaxLen);
    if (reqHeadData == NULL) {
        ATTEST_LOG_ERROR("[BuildHttpsHead] reqHeadData ATTEST MEM MALLOC fail");
        return ATTEST_ERR;
    }
    int newLen = sprintf_s(reqHeadData, headerMaxLen, HTTPS_POST_FORMAT, FILL_HTTPS_POST_FORMAT_ARGS(msgHttpPack));
    ATTEST_MEM_FREE(msgHttpPack.reqXclientID);
    ATTEST_MEM_FREE(msgHttpPack.reqXtraceID);
    if (newLen <= 0) {
        ATTEST_MEM_FREE(reqHeadData);
        ATTEST_LOG_ERROR("[BuildHttpsHead] reqHeadData sprintf_s fail");
        return ATTEST_ERR;
    }
    *headData = reqHeadData;
    ATTEST_LOG_DEBUG("[BuildHttpsHead] End.");
    return ATTEST_OK;
}

static int32_t BuildTokenInfo(DevicePacket *postValue, cJSON **postData)
{
    if (postValue == NULL || postData == NULL) {
        ATTEST_LOG_ERROR("[BuildTokenInfo] Invaild parameter");
        return ATTEST_ERR;
    }
    cJSON *tokenInfo = cJSON_CreateObject();
    if (tokenInfo == NULL) {
        ATTEST_LOG_ERROR("[BuildTokenInfo] tokenInfo Create Object fail");
        return ATTEST_ERR;
    }
    if (!cJSON_AddItemToObject(*postData, "tokenInfo", tokenInfo)) {
        ATTEST_LOG_ERROR("[BuildTokenInfo] tokenInfo Add Item To Object fail");
        cJSON_Delete(tokenInfo);
        return ATTEST_ERR;
    }
    if (cJSON_AddStringToObject(tokenInfo, "uuid", postValue->tokenInfo.uuid) == NULL ||
        cJSON_AddStringToObject(tokenInfo, "token", postValue->tokenInfo.token) == NULL) {
        ATTEST_LOG_ERROR("[BuildTokenInfo] tokenInfo Add uuid or token fail");
        cJSON_Delete(tokenInfo);
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}

static int32_t Buildsoftware(DevicePacket *postValue, cJSON **postData)
{
    if (postValue == NULL || postData == NULL) {
        ATTEST_LOG_ERROR("[Buildsoftware] Invaild parameter");
        return ATTEST_ERR;
    }

    cJSON *software = cJSON_CreateObject();
    if (software == NULL) {
        ATTEST_LOG_ERROR("[Buildsoftware] software Create Object fail");
        return ATTEST_ERR;
    }
    if (!cJSON_AddItemToObject(*postData, "software", software)) {
        ATTEST_LOG_ERROR("[Buildsoftware] postData Add Item To Object fail");
        cJSON_Delete(software);
        return ATTEST_ERR;
    }
    if (cJSON_AddStringToObject(software, "versionId", postValue->productInfo.versionId) == NULL ||
        cJSON_AddStringToObject(software, "manufacture", postValue->productInfo.manu) == NULL ||
        cJSON_AddStringToObject(software, "model", postValue->productInfo.model) == NULL ||
        cJSON_AddStringToObject(software, "brand", postValue->productInfo.brand) == NULL ||
        cJSON_AddStringToObject(software, "rootHash", postValue->productInfo.rootHash) == NULL ||
        cJSON_AddStringToObject(software, "version", postValue->productInfo.displayVersion) == NULL ||
        cJSON_AddStringToObject(software, "patchLevel", postValue->productInfo.patchTag) == NULL ||
        cJSON_AddStringToObject(software, "pcid", postValue->pcid) == NULL) {
        ATTEST_LOG_ERROR("[Buildsoftware] software Add productInfo values fail");
        cJSON_Delete(software);
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}

char* BuildHttpsChallBody(DevicePacket *postValue)
{
    ATTEST_LOG_DEBUG("[BuildHttpsChallBody] Begin.");
    if (postValue == NULL) {
        ATTEST_LOG_ERROR("[BuildHttpsChallBody] Invalid parameter postValue");
        return NULL;
    }
    cJSON *postData = cJSON_CreateObject();
    if (postData == NULL) {
        ATTEST_LOG_ERROR("[BuildHttpsChallBody] postData  CreateObject fail");
        return NULL;
    }
    if (cJSON_AddStringToObject(postData, "uniqueId", postValue->udid) == NULL) {
        cJSON_Delete(postData);
        ATTEST_LOG_ERROR("[BuildHttpsChallBody] postData  AddStringToObject fail");
        return NULL;
    }
    char *bodyData = cJSON_Print(postData);
    cJSON_Delete(postData);
    ATTEST_LOG_DEBUG("[BuildHttpsChallBody] End.");
    return bodyData;
}

char* BuildHttpsResetBody(DevicePacket *postValue)
{
    ATTEST_LOG_DEBUG("[BuildHttpsResetBody] Begin.");
    if (postValue == NULL) {
        ATTEST_LOG_ERROR("[BuildHttpsResetBody] Invalid parameter");
        return NULL;
    }
    cJSON *postData = cJSON_CreateObject();
    if (postData == NULL) {
        ATTEST_LOG_ERROR("[BuildHttpsResetBody] postData CreateObject fail");
        return NULL;
    }
    int32_t ret = ATTEST_OK;
    do {
        if (cJSON_AddStringToObject(postData, "udid", postValue->udid) == NULL) {
            ATTEST_LOG_ERROR("[BuildHttpsResetBody] udid Add String To Object fail");
            ret = ATTEST_ERR;
            break;
        }
        ret = BuildTokenInfo(postValue, &postData);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[BuildHttpsResetBody] postData CreateObject fail");
            break;
        }
    } while (0);
    if (ret != ATTEST_OK) {
        cJSON_Delete(postData);
        ATTEST_LOG_ERROR("[BuildHttpsResetBody] postObj  add value fail");
        return NULL;
    }
    char *bodyData = cJSON_Print(postData);
    cJSON_Delete(postData);
    if (ATTEST_NETWORK_DEBUG_LOG_FLAG) {
        ATTEST_LOG_DEBUG("[BuildHttpsResetBody] ResetBody [%u]\n%s\n", strlen(bodyData), bodyData);
    }
    ATTEST_LOG_DEBUG("[BuildHttpsResetBody] End.");
    return bodyData;
}

char* BuildHttpsAuthBody(DevicePacket *postValue)
{
    ATTEST_LOG_DEBUG("[BuildHttpsAuthBody] Begin.");
    if (postValue == NULL) {
        ATTEST_LOG_ERROR("[BuildHttpsAuthBody] Invalid parameter");
        return NULL;
    }
    cJSON *postData = cJSON_CreateObject();
    if (postData == NULL) {
        ATTEST_LOG_ERROR("[BuildHttpsAuthBody] postData CreateObject fail");
        return NULL;
    }
    int32_t ret = ATTEST_OK;
    do {
        if (cJSON_AddStringToObject(postData, "udid", postValue->udid) == NULL) {
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[BuildHttpsAuthBody] udid Add String To Object fail");
            break;
        }

        ret = BuildTokenInfo(postValue, &postData);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[BuildHttpsAuthBody] tokenInfo Add item To Object fail");
            break;
        }

        ret = Buildsoftware(postValue, &postData);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[BuildHttpsAuthBody] software Add item To Object fail");
            break;
        }
    } while (0);
    if (ret != ATTEST_OK) {
        cJSON_Delete(postData);
        ATTEST_LOG_ERROR("[BuildHttpsAuthBody] postData extract values fail");
        return NULL;
    }
    char *bodyData = cJSON_Print(postData);
    cJSON_Delete(postData);
    if (ATTEST_NETWORK_DEBUG_LOG_FLAG) {
        ATTEST_LOG_DEBUG("[BuildHttpsAuthBody] AuthBody [%u]\n%s\n", strlen(bodyData), bodyData);
    }
    ATTEST_LOG_DEBUG("[BuildHttpsAuthBody] End.");
    return bodyData;
}

char* BuildHttpsActiveBody(DevicePacket *postValue)
{
    ATTEST_LOG_DEBUG("[BuildHttpsActiveBody] Begin.");
    if (postValue == NULL) {
        ATTEST_LOG_ERROR("[BuildHttpsActiveBody] Invalid parameter");
        return NULL;
    }
    cJSON *postData = cJSON_CreateObject();
    if (postData == NULL) {
        ATTEST_LOG_ERROR("[BuildHttpsActiveBody] postData CreateObject fail");
        return NULL;
    }
    int32_t ret = ATTEST_OK;
    do {
        if (cJSON_AddStringToObject(postData, "ticket", postValue->ticket) == NULL ||
            cJSON_AddStringToObject(postData, "udid", postValue->udid) == NULL) {
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[BuildHttpsActiveBody] postData Add ticket or udid fail");
            break;
        }

        ret = BuildTokenInfo(postValue, &postData);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[BuildHttpsAuthBody] tokenInfo Add item To Object fail");
            break;
        }
    } while (0);
    if (ret != ATTEST_OK) {
        cJSON_Delete(postData);
        ATTEST_LOG_ERROR("[BuildHttpsActiveBody] postData extract values by postValue fail");
        return NULL;
    }
    char *bodyData = cJSON_Print(postData);
    cJSON_Delete(postData);
    if (ATTEST_NETWORK_DEBUG_LOG_FLAG) {
        ATTEST_LOG_DEBUG("[BuildHttpsActiveBody] ActiBody [%u]\n%s\n", strlen(bodyData), bodyData);
    }
    ATTEST_LOG_DEBUG("[BuildHttpsActiveBody] End.");
    return bodyData;
}

static int32_t BuildHttpsBody(DevicePacket *devData, ATTEST_ACTION_TYPE actionType, char **outBody)
{
    if (actionType >= ATTEST_ACTION_MAX) {
        ATTEST_LOG_ERROR("[BuildHttpsBody] actionType out of range");
        return ATTEST_ERR;
    }
    
    BuildBodyFunc buildBodyFunc = g_buildBodyFunc[actionType];
    if (buildBodyFunc == NULL) {
        ATTEST_LOG_ERROR("[BuildHttpsBody] g_buildBodyFunc fail");
        return ATTEST_ERR;
    }
    char *postBody = buildBodyFunc(devData);
    if (postBody == NULL) {
        ATTEST_LOG_ERROR("[BuildHttpsBody] buildBodyFunc fail");
        return ATTEST_ERR;
    }
    *outBody = postBody;
    return ATTEST_OK;
}

static int32_t BuildHttpsMsg(char *header, char *body, char **outMsg)
{
    if (header == NULL || body == NULL || outMsg == NULL) {
        ATTEST_LOG_ERROR("[BuildHttpsMsg] Invalid parameter");
        return ATTEST_ERR;
    }

    uint32_t headerLen = strlen(header);
    uint32_t bodyLen = strlen(body);
    if (headerLen == 0 || bodyLen == 0) {
        ATTEST_LOG_ERROR("[BuildHttpsMsg] headerLen or bodyLen is ZERO");
        return ATTEST_ERR;
    }
    
    uint32_t msgLen = headerLen + bodyLen + 1;
    char *msg = (char *)ATTEST_MEM_MALLOC(msgLen);
    if (msg == NULL) {
        ATTEST_LOG_ERROR("[BuildHttpsMsg] msg ATTEST_MEM_MALLOC fail");
        return ATTEST_ERR;
    }

    int32_t ret = memcpy_s(msg, msgLen, header, headerLen);
    if (ret != 0) {
        ATTEST_MEM_FREE(msg);
        ATTEST_LOG_ERROR("[BuildHttpsMsg] header memcpy_s fail");
        return ATTEST_ERR;
    }
    ret = memcpy_s(msg + headerLen, msgLen - headerLen, body, bodyLen);
    if (ret != 0) {
        ATTEST_MEM_FREE(msg);
        ATTEST_LOG_ERROR("[BuildHttpsMsg] body memcpy_s fail");
        return ATTEST_ERR;
    }
    *outMsg = msg;
    return ATTEST_OK;
}

static int32_t GenHttpsMsg(DevicePacket *devPacket, ATTEST_ACTION_TYPE actionType, char  **reqMsg)
{
    if (devPacket == NULL || reqMsg == NULL) {
        ATTEST_LOG_ERROR("[GenHttpsMsg] Invalid parameter");
        return ATTEST_ERR;
    }

    char *msg = NULL;
    char *header = NULL;
    char *body = NULL;
    int32_t retCode;
    do {
        retCode = BuildHttpsBody(devPacket, actionType, &body);
        if (retCode != ATTEST_OK) {
            ATTEST_LOG_ERROR("[GenHttpsMsg] BuildHttpsBody fail");
            break;
        }
        retCode = BuildHttpsHead(devPacket, strlen(body), actionType, &header);
        if (retCode != ATTEST_OK) {
            ATTEST_LOG_ERROR("[GenHttpsMsg] BuildHttpsHead fail");
            break;
        }
        retCode = BuildHttpsMsg(header, body, &msg);
        if (retCode != ATTEST_OK) {
            ATTEST_LOG_ERROR("[GenHttpsMsg] BuildHttpsMsg fail");
            break;
        }
    } while (0);
    ATTEST_MEM_FREE(header);
    ATTEST_MEM_FREE(body);
    if (retCode != ATTEST_OK) {
        ATTEST_MEM_FREE(msg);
        ATTEST_LOG_ERROR("[GenHttpsMsg] Build Https Msg fail");
        return ATTEST_ERR;
    }
    *reqMsg = msg;

    return ATTEST_OK;
}

static int32_t SendHttpsMsg(char *postData, char **respData)
{
    /* 判断入参合法性 */
    if (postData == NULL || respData == NULL) {
        ATTEST_LOG_ERROR("[SendHttpsMsg] Invalid parameter.");
        return ATTEST_ERR;
    }
    int32_t ret = ATTEST_ERR;
    int32_t socketFd = -1;
    SSL *postSSL = NULL;
    do {
        ret = InitSocketClient(&socketFd);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[SendHttpsMsg] Init Socket Client is fail, ret = %d.", ret);
            break;
        }

        ret = InitSSLSocket(socketFd, &postSSL);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[SendHttpsMsg] Init SSL Socket is fail, ret = %d.", ret);
            break;
        }
        /* CA证书检验 */
        ret = VerifySSLCA(postSSL);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[SendHttpsMsg] Verify SSL CA is fail, ret = %d.", ret);
            break;
        }
        /* 发送数据请求           */
        int32_t postDataLen = strlen(postData) + 1;
        int32_t writeCnt = SendSSL(postSSL, postData, postDataLen);
        if (writeCnt != postDataLen) {
            ATTEST_LOG_ERROR("[SendHttpsMsg] Send SSL failed, needLen = %d, realLen = %d\n", postDataLen, writeCnt);
            break;
        }
        /* 返回请求结果 */
        ret = RecvSSL(postSSL, respData);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[SendHttpsMsg] HttpsPost RecvSSL is fail, ret = %d.", ret);
            break;
        }
    } while (0);
    if (socketFd != -1) {
        close(socketFd);
    }
    if (postSSL != NULL) {
        SSL_free(postSSL);
    }
    return ret;
}

static int32_t ParseHttpsRespIntPara(char *respMsg, int32_t httpType, int32_t *intPara)
{
    if (respMsg == NULL || intPara == NULL || httpType >= ATTEST_HTTPS_MAX) {
        ATTEST_LOG_ERROR("[ParseHttpsRespIntPara] Invalid parameter.");
        return ATTEST_ERR;
    }
    
    char *httpTypeStr = g_httpHeaderName[httpType];
    if (httpTypeStr == NULL) {
        ATTEST_LOG_ERROR("[ParseHttpsRespIntPara] g_httpHeaderName fail.");
        return ATTEST_ERR;
    }
    
    char *appearAddr = strstr(respMsg, httpTypeStr);
    if (appearAddr == NULL) {
        ATTEST_LOG_ERROR("[ParseHttpsRespIntPara]Find httpName in response msg fail, httpName = %s.", httpTypeStr);
        return ATTEST_ERR;
    }

    char *httpValueAddr = appearAddr + strlen(httpTypeStr) + 1;
    int32_t len = 0;
    while (isdigit(httpValueAddr[len])) {
        len++;
    }

    char *httpValue = (char *)ATTEST_MEM_MALLOC(len + 1);
    if (httpValue == NULL) {
        ATTEST_LOG_ERROR("[ParseHttpsRespIntPara] httpValue ATTEST_MEM_MALLOC fail.");
        return ATTEST_ERR;
    }

    int32_t retCode = memcpy_s(httpValue, len + 1, httpValueAddr, len);
    if (retCode != ATTEST_OK) {
        ATTEST_MEM_FREE(httpValue);
        ATTEST_LOG_ERROR("[ParseHttpsRespIntPara] httpValueAddr memcpy_s fail.");
        return ATTEST_ERR;
    }

    *intPara = atoi(httpValue);
    ATTEST_MEM_FREE(httpValue);
    return ATTEST_OK;
}

static int32_t ParseHttpsResp(char *respMsg, char **outBody)
{
    int32_t httpRetCode = 0;
    int32_t retCode = ParseHttpsRespIntPara(respMsg, ATTEST_HTTPS_RESCODE, &httpRetCode);
    if ((retCode != ATTEST_OK) || (httpRetCode != HTTP_OK)) {
        ATTEST_LOG_ERROR("[ParseHttpsResp] Parse return code failed, ret = %d, httpCode =  %d.", retCode, httpRetCode);
        return ATTEST_ERR;
    }
    
    int32_t contentLen = 0;
    retCode = ParseHttpsRespIntPara(respMsg, ATTEST_HTTPS_RESLEN, &contentLen);
    if (retCode != ATTEST_OK || contentLen == 0) {
        ATTEST_LOG_ERROR("[ParseHttpsResp] Parse content length failed, ret = %d, length =  %d.", retCode, contentLen);
        return ATTEST_ERR;
    }

    char *body = (char *)ATTEST_MEM_MALLOC(contentLen + 1);
    if (body == NULL) {
        ATTEST_LOG_ERROR("[ParseHttpsResp] body ATTEST_MEM_MALLOC fail.");
        return ATTEST_ERR;
    }
    uint32_t headerLen = strlen(respMsg) - contentLen;
    retCode = memcpy_s(body, contentLen + 1, respMsg + headerLen, contentLen);
    if (retCode != ATTEST_OK) {
        ATTEST_MEM_FREE(body);
        ATTEST_LOG_ERROR("[ParseHttpsResp] respMsg + headerLen memcpy_s fail.");
        return ATTEST_ERR;
    }
    *outBody = body;
    return ATTEST_OK;
}

int32_t SendAttestMsg(DevicePacket *devPacket, ATTEST_ACTION_TYPE actionType, char **respBody)
{
    ATTEST_LOG_DEBUG("[SendAttestMsg] Begin.");
    char *reqData = NULL;
    char *respData = NULL;
    int32_t retCode;
    if (devPacket == NULL || respBody == NULL) {
        ATTEST_LOG_ERROR("[SendAttestMsg] Input Parameter is null.");
        return ATTEST_ERR;
    }

    do {
        retCode = GenHttpsMsg(devPacket, actionType, &reqData);
        if (retCode != ATTEST_OK) {
            ATTEST_LOG_ERROR("[SendAttestMsg] Generate https msg fail, retCode = %d.", retCode);
            break;
        }
        retCode = SendHttpsMsg(reqData, &respData);
        if (retCode != ATTEST_OK) {
            ATTEST_LOG_ERROR("[SendAttestMsg] Send https msg failed, retCode = %d.", retCode);
            break;
        }
        retCode = ParseHttpsResp(respData, respBody);
        if (retCode != ATTEST_OK) {
            ATTEST_LOG_ERROR("[SendAttestMsg] Parse response failed, retCode = %d.", retCode);
            break;
        }
    } while (0);
    ATTEST_MEM_FREE(reqData);
    ATTEST_MEM_FREE(respData);
    ATTEST_LOG_DEBUG("[SendAttestMsg] End.");
    return retCode;
}

static int32_t SplitNetworkInfoSymbol(char *inputData, List *list)
{
    if (inputData == NULL || list == NULL) {
        ATTEST_LOG_ERROR("[SplitNetworkInfoSymbol] paramter wrong.");
        return ATTEST_ERR;
    }

    ServerInfo* networkServerInfo = (ServerInfo*)ATTEST_MEM_MALLOC(sizeof(ServerInfo));
    if (networkServerInfo == NULL) {
        ATTEST_LOG_ERROR("[SplitNetworkInfoSymbol] network infomation malloc failed.");
        return ATTEST_ERR;
    }

    int32_t ret = sscanf_s(inputData, "%" HOST_PATTERN ":%" PORT_PATTERN,
        networkServerInfo->hostName, MAX_HOST_NAME_LEN,
        networkServerInfo->port, MAX_PORT_LEN);

    if (ret != PARAM_TWO) {
        ATTEST_LOG_ERROR("[SplitNetworkInfoSymbol] failed to split NetworkInfo, host[%s] port[%s]",
            networkServerInfo->hostName, networkServerInfo->port);
        ATTEST_MEM_FREE(networkServerInfo);
        return ATTEST_ERR;
    }
    ret = AddListNode(list, (char *)networkServerInfo);
    return ret;
}

static int32_t ParseNetworkInfosConfig(char *inputData, List *list)
{
    if (inputData == NULL || list == NULL) {
        ATTEST_LOG_ERROR("[ParseNetworkInfoConfig] parameter wrong.");
        return ATTEST_ERR;
    }

    cJSON* root = cJSON_Parse(inputData);
    if (root == NULL) {
        ATTEST_LOG_ERROR("[ParseNetworkInfoConfig] failed to parse json.");
        return ATTEST_ERR;
    }

    int32_t ret = ATTEST_OK;
    do {
        char *valueString = cJSON_GetStringValue(cJSON_GetObjectItem(root, NETWORK_CONFIG_SERVER_INFO_NAME));
        if (valueString == NULL) {
            ATTEST_LOG_ERROR("[ParseNetworkInfosConfig] failed to get string");
            ret = ATTEST_ERR;
            break;
        }

        ret = SplitNetworkInfoSymbol(valueString, list);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ParseNetworkInfosConfig] failed to get SplitNetworkInfo");
            break;
        }
    } while (0);

    cJSON_Delete(root);
    return ret;
}

static int32_t NetworkInfoConfig(List* list)
{
    if (list == NULL) {
        ATTEST_LOG_ERROR("[NetworkInfoConfig] paramter wrong");
        return ATTEST_ERR;
    }

    // No need to initialize
    if (GetListSize(list) != 0) {
        ATTEST_LOG_WARN("[NetworkInfoConfig] already configed network list");
        return ATTEST_OK;
    }

    int32_t ret = CreateList(list);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[NetworkInfoConfig] create network list failed");
        return ATTEST_ERR;
    }

    // For reading network_config.json
    char *buffer = (char *)ATTEST_MEM_MALLOC(NETWORK_CONFIG_SIZE + 1);
    if (buffer == NULL) {
        ATTEST_LOG_ERROR("[NetworkInfoConfig] buffer malloc failed.");
        ReleaseList(list);
        return ATTEST_ERR;
    }
    do {
        ret = AttestReadNetworkConfig(buffer, NETWORK_CONFIG_SIZE);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[NetworkInfoConfig] read networkconfig failed.");
            break;
        }

        ret = ParseNetworkInfosConfig(buffer, list);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[NetworkInfoConfig] parse networkconfig failed.");
            break;
        }
    } while (0);
    if (ret != ATTEST_OK) {
        ReleaseList(list);
    }
    ATTEST_MEM_FREE(buffer);
    return ret;
}

int32_t InitNetworkServerInfo(void)
{
    if (g_attestNetworkList.head != NULL) {
        ATTEST_LOG_WARN("[InitNetworkServerInfo] already init g_attestNetworkList");
        return ATTEST_OK;
    }
    int32_t ret = NetworkInfoConfig(&g_attestNetworkList);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_INFO("[InitNetworkServerInfo] init g_attestNetworkList failed");
        return ret;
    }
    return ATTEST_OK;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
