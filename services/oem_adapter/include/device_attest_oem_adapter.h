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

#ifndef DEVICE_ATTEST_OEM_ADAPTER_H
#define DEVICE_ATTEST_OEM_ADAPTER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define TOKEN_SIZE 151
#define TOKEN_FLAG_SIZE 4
#define TOKEN_WITH_FLAG_SIZE (TOKEN_SIZE + TOKEN_FLAG_SIZE)
#define TOKEN_ADDR "/data/device_attest"
#define TOKEN_A_ADDR "tokenA"
#define TOKEN_B_ADDR "tokenB"
#define BITS_PER_BYTE 8

/**
 * @brief Get Manufacturekey value from device.
 *
 * @param manufacturekey : the result Manufacturekey, if get successfully.
 * @param len : length of the acKey.
 * @returns 0 if success, otherwise -1.
 */
int32_t OEMGetManufacturekey(char* manufacturekey, uint32_t len);

/**
 * @brief Get ProdId value from device.
 *
 * @param productId : product IDs to be populated with.
 * @param len : length of the productId.
 * @returns 0 if success, otherwise -1.
 */
int32_t OEMGetProductId(char* productId, uint32_t len);

/**
 * @brief Read token value from device.
 *
 * @param token : the result token value, if read successfully.
 * @param len : length of the token.
 * @returns 0 if success and get the update area token,
 *         -1 if failed,
 *         -2 if no pre-made token.
 */
int32_t OEMReadToken(char *token, uint32_t len);

/**
 * @brief Write token value to device.
 *
 * @param token : the token to write.
 * @param len : length of the token.
 * @returns 0 if success, otherwise -1.
 */
int32_t OEMWriteToken(const char *token, uint32_t len);

/**
 * @brief Get ProdKey value from device.
 *
 * @param productKey : The productKey value
 * @param len : The productKey len.
 * @returns 0 if success, otherwise -1.
 */
int32_t OEMGetProductKey(char* productKey, uint32_t len);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif
