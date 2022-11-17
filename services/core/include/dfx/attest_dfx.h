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

#ifndef __ATTEST_DFX_H__
#define __ATTEST_DFX_H__

#ifdef __cplusplus
#if __cplusplus
    extern "C" {
#endif
#endif /* __cplusplus */

#ifdef __ATTEST_DEBUG_DFX__
#define ATTEST_DEBUG_DFX true
#else
#define ATTEST_DEBUG_DFX false
#endif

void PrintChallengeResult(ChallengeResult* challengeResult);

void PrintDevicePacket(DevicePacket* devicePacket);

void PrintDeviceTokenInfo(DeviceTokenInfo* tokenInfo);

void PrintDeviceProductInfo(DeviceProductInfo *productInfo);

void PrintAuthResult(AuthResult* authResult);

void PrintAuthStatus(AuthStatus* authStatus);

void PrintTokenInfo(TokenInfo* tokenInfo);

void PrintTicketInfo(TicketInfo* ticketInfo);

#define ATTEST_DFX_CHALL_RESULT(d_challengeResult) PrintChallengeResult((ChallengeResult*)(d_challengeResult))

#define ATTEST_DFX_DEV_PACKET(d_devicePacket) PrintDevicePacket((DevicePacket*)(d_devicePacket))

#define ATTEST_DFX_DEV_TOKEN(d_tokenInfo) PrintDeviceTokenInfo((DeviceTokenInfo*)(d_tokenInfo))

#define ATTEST_DFX_DEV_PDT(d_productInfo) PrintDeviceProductInfo((DeviceProductInfo *)(d_productInfo))
    
#define ATTEST_DFX_AUTH_RESULT(d_authResult) PrintAuthResult((AuthResult*)(d_authResult))
    
#define ATTEST_DFX_AUTH_STATUS(d_authStatus) PrintAuthStatus((AuthStatus*)(d_authStatus))
    
#define ATTEST_DFX_TOKEN_INFO(d_tokenInfo) PrintTokenInfo((TokenInfo*)(d_tokenInfo))
    
#define ATTEST_DFX_TICKET_INFO(d_ticketInfo) PrintTicketInfo((TicketInfo*)(d_ticketInfo))

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif
