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

#include <securec.h>
#include <stdlib.h>
#include "string.h"
#include "attest_error.h"
#include "attest_utils.h"
#include "attest_utils_list.h"

const uint32_t MAX_LIST_LENGTH = 2048;

int32_t CreateList(List *list)
{
    if (list == NULL) {
        return ERR_INVALID_PARAM;
    }
    list->head = NULL;
    return ATTEST_OK;
}

int32_t AddListNode(List *list, void *data)
{
    if (list == NULL || data == NULL) {
        return ERR_INVALID_PARAM;
    }
    ListNode* head = list->head;
    uint32_t size = 1;
    if (head == NULL) {
        size = 0;
    }

    while (head != NULL && head->next != NULL) {
        head = head->next;
        size++;
    }
    if (size >= MAX_LIST_LENGTH) {
        return ERR_OUT_CAPACITY;
    }

    ListNode* node = (ListNode *)ATTEST_MEM_MALLOC(sizeof(ListNode));
    if (node == NULL) {
        return ERR_SYSTEM_CALL;
    }

    node->data = data;
    node->next = NULL;
    if (list->head == NULL) {
        list->head = node;
    } else if (head != NULL) {
        head->next = node;
    }
    return ATTEST_OK;
}

int32_t GetListSize(List *list)
{
    if (list == NULL) {
        return ATTEST_ERR;
    }
    int32_t size = 0;
    ListNode* head = list->head;
    while (head != NULL) {
        head = head->next;
        size++;
    }
    return size;
}

void ReleaseList(List *list)
{
    if (list == NULL) {
        return;
    }

    ListNode* head = list->head;
    ListNode* temp = head;
    while (head != NULL) {
        temp = head;
        head = head->next;
        ATTEST_MEM_FREE(temp->data);
        ATTEST_MEM_FREE(temp);
    }
    list->head = NULL;
}

