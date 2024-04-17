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
#ifndef ATTEST_TDD_MOCK_HAL_H
#define ATTEST_TDD_MOCK_HAL_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

void AttestSetMockReadTokenRet(int value);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#define ATTEST_MOCK_HAL_MANU_KEY "1234567890abcdef1234567890abcdef1234567890abcdef\
1234567890abcdef1234567890abcdef1234567890abcdef"
#define ATTEST_MOCK_HAL_MANU_KEY_LEN 96

#define ATTEST_MOCK_HAL_PRO_ID "OH00Test"
#define ATTEST_MOCK_HAL_PRO_ID_LEN 8

#define ATTEST_MOCK_HAL_PRO_KEY "test"

// tokenDecrypted "1Attest+-3Token*4Value/5=Test1e1"
#define ATTEST_FIRST_TOKENID    "e10oVXrrR8Ra9LHXuorJ8PrwwWn/RUYinPiUbFAkA0ucJA1+IUhZ5GNsacn5vnWo"
#define ATTEST_FIRST_TOKEVALUE  "e10oVXrrR8Ra9LHXuorJ8PrwwWn/RUYinPiUbFAkA0ucJA1+IUhZ5GNsacn5vnWo"
#define ATTEST_FIRST_SALT       "Sa/lt+123Te-stX="
#define ATTEST_FIRST_VERSION    "1000"

#define ATTEST_CASE_RESET 1
#define ATTEST_RESET_CHAP "39a9d04d41617162893c3312ceb030acac8d8bd0cc9fcebcab5402a43891341d"
#define ATTEST_RESET_CHAP_TIME 1234567890
#define ATTEST_RESET_GEN_TOKEN "ldV+D/FnxYLwL3myrVLXmLTvKi92WTGQgPAk5r6KAcg="
// tokenDecrypted "QZYbv4NdQ1oPy9zCsh2RjOpleFNd6DDA"
#define ATTEST_RESET_GEN_PRODUCT_TOKEN "J9gNiIq3cjhWYv7rMrbEkFzHeEh3Hl9561+Taqdv7gY="
// tokenDecrypted "AKXOFdCBwi3sHQy+YYEYM7U+WqZE1B5W"
#define ATTEST_RESET_GEN_ONLINE_TOKEN "n2wSEwmXnYWEsSqN4yngtnt1HGO5NqS/nhj6F2DG0js="
#define ATTEST_RESET_GEN_ONLINE_TOKEN_ID "f1feb9b7-bde2-0ee7-3089-49277d648666"

#define ATTEST_CASE_AUTH 2
#define ATTEST_AUTH_EXPECT_RESULT "{\"authStats\":\".eyJhdXRoUmVzdWx0IjowLCJhdXRoVHlwZSI6IlRPS0VOX0VO\
QUJMRSIsImV4cGlyZVRpbWUiOjE2ODMzNzM2NzE2NzQsImtpdFBvbGljeSI6W10sInNvZnR3YXJlUmVzdWx0IjozMDAwMiwic29mdHdhcmVSZXN1bHRE\
ZXRhaWwiOnsicGF0Y2hMZXZlbFJlc3VsdCI6MzAwMDgsInBjaWRSZXN1bHQiOjMwMDExLCJyb290SGFzaFJlc3VsdCI6MzAwMDksInZlcnNpb25JZFJlc\
3VsdCI6MzAwMDJ9LCJ1ZGlkIjoiODFDOTQ0NTI3OUEzQTQxN0Q0MTU5RkRGQzYyNjkxQkM4REEwMDJFODQ2M0M3MEQyM0FCNENCRjRERjk4MjYxQy\
IsInZlcnNpb25JZCI6ImRlZmF1bHQvaHVhLXdlaS9rZW1pbi9kZWZhdWx0L09wZW5IYXJtb255LTQuMC4zLjIoQ2FuYXJ5MSkvb2hvcy9tYXgvMTAv\
T3Blbkhhcm1vbnkgMi4zIGJldGEvZGVidWcifQ.\",\
\"errcode\":0,\
\"ticket\":\"svnR0unsciaFi7S4hcpBa/LCSiYwNSt6\",\
\"token\":\"yh9te54pfTb91CrSqpD5fQsVBA/etKNb\",\
\"uuid\":\"156dcff8-0ab0-4521-ac8f-ba682e6ca5a0\"\
}3"
#define ATTEST_AUTH_CHAP "a81441e3c0d8d6a78907fa0888f9241be9591c4d6b7a533318b010fb2c3d9b80"
#define ATTEST_AUTH_CHAP_TIME 1234567890
#define ATTEST_AUTH_GEN_TOKEN "hVWBm7/Rspndlt9jou8+dmJ2LFiToesDeFV4+Qrjs2A="
// product token
#define ATTEST_AUTH_GEN_PRODUCT_TOKEN "W8QPcxhymyPI5T/43Jh9JpOz3R6LdAqxTiWTFvHH0xY="
// tokenDecrypted "AKXOFdCBwi3sHQy+YYEYM7U+WqZE1B5W"
#define ATTEST_AUTH_GEN_ONLINE_TOKEN "sQW7UN8eUGOuWRYvryvoLEL+4LfDOxVUniJy2kkjt/U="

#define ATTEST_CASE_ACTIVE 3
#define ATTEST_ACTIVE_CHAP "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
#define ATTEST_ACTIVE_CHAP_TIME 1234567890
#define ATTEST_ACTIVE_GEN_TOKEN "NwccOBLvwgb5+Far1tj+zGcitRg8LAYafZn2lu4UiGE="
// product token
#define ATTEST_ACTIVE_GEN_PRODUCT_TOKEN "acQK/fx9oYVuLyk04MITltw8xLegbPiBf3bqtLkhVDc="
// tokenDecrypted "AKXOFdCBwi3sHQy+YYEYM7U+WqZE1B5W"
#define ATTEST_ACTIVE_GEN_ONLINE_TOKEN "v7kYS5P+JM2uWHLrIAVHIwckm8pyfInPHx1SHugPJe0="

#define ATTEST_MOCK_HAL_TICKET "svnR0unsciaFi7S4hcpBa/LCSiYwNSt6"
#define ATTEST_MOCK_HAL_TICKET_LEN 32

#define ATTEST_MOCK_HAL_STATUS ".eyJhdXRoUmVzdWx0IjowLCJhdXRoVHlwZSI6IlRPS0VOX0VOQUJMRSI\
sImV4cGlyZVRpbWUiOjE2ODMzNzM2NzE2NzQsImtpdFBvbGljeSI6W10sInNvZnR3YXJlUmVzdWx0IjozMDAwMiwic29mdHdhcmVSZXN1bHREZXRh\
aWwiOnsicGF0Y2hMZXZlbFJlc3VsdCI6MzAwMDgsInBjaWRSZXN1bHQiOjMwMDExLCJyb290SGFzaFJlc3VsdCI6MzAwMDksInZlcnNpb25JZFJlc\
3VsdCI6MzAwMDJ9LCJ1ZGlkIjoiODFDOTQ0NTI3OUEzQTQxN0Q0MTU5RkRGQzYyNjkxQkM4REEwMDJFODQ2M0M3MEQyM0FCNENCRjRERjk4MjYxQy\
IsInZlcnNpb25JZCI6ImRlZmF1bHQvaHVhLXdlaS9rZW1pbi9kZWZhdWx0L09wZW5IYXJtb255LTQuMC4zLjIoQ2FuYXJ5MSkvb2hvcy9tYXgvMTAv\
T3Blbkhhcm1vbnkgMi4zIGJldGEvZGVidWcifQ."
#define ATTEST_MOCK_HAL_STATUS_LEN 548

#define ATTEST_HARDWARE_RESULT 0
#define ATTEST_AUTH_TYPE "TOKEN_ENABLE"
#define ATTEST_EXPIRE_TIME 1683373671674
#define ATTEST_VERSION_ID "default/hua-wei/kemin/default/OpenHarmony-4.0.3.2(Canary1)/ohos/max/10\
/OpenHarmony 2.3 beta/debug"
#define ATTEST_SOFTWARE_RESULT 30002

#define ATTEST_MOCK_HAL_NETWORK_CONFIG "{\"serverInfo\":\"testserver:443\"}"
#define ATTEST_MOCK_HAL_NETWORK_CONFIG_LEN 256
#define ATTEST_MOCK_HAL_NETWORK_RESULT "testserver"

#define ATTEST_RESULT_CODE 0
#define ATTEST_RESULT_CODE_LEN 1

#endif