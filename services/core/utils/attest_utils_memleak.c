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

#include "attest_type.h"
#include "attest_utils_list.h"
#include "attest_utils_log.h"
#include "attest_utils_memleak.h"

// 注意：该文件只调用本文件函数，禁止调用外部函数，避免出现循环依赖。

/*
   内存泄漏检测实现流程：
1、认证流程开始时，初始化内存链表。记录申请内存节点，节点信息包括地址、文件、函数、行数。
2、处理流程中：
  1）申请内存时，向内存链表添加节点，最多添加2048个节点。
  2）释放内存时，从节点中删除节点，其中key为地址信息。
3、认证流程结束，打印内存链表，释放内存链表。
   如有链表有节点，说明有内存泄漏，当前只支持hilog输出。
4、需要注意：
   1) 申请内存和释放内存使用自定义函数，配对使用，否则跟踪不到内存申请。
   ATTEST_MEM_MALLOC/ATTEST_MEM_FREE
   2) 部分系统或三方函数内部申请内存，因此跟踪不到内存申请，需要使用原生free进行释放。
   3) 内存检测模块占用内存较多，使用宏控制，仅供检测内存场景，正常场景需要关闭掉。
*/
const uint32_t MAX_MEM_NODE_LIST_LENGTH = 2048;

List *g_memNodeList = NULL;

int32_t InitMemNodeList(void)
{
    if (g_memNodeList != NULL) {
        ATTEST_LOG_ERROR("[InitMemNodeList] g_memNodeList is not null");
        return ATTEST_OK;
    }
    List* list = (List *)malloc(sizeof(List));
    if (list == NULL) {
        return ATTEST_ERR;
    }
    (void)memset_s(list, sizeof(List), 0, sizeof(List));
    list->head = NULL;
    g_memNodeList = list;
    return ATTEST_OK;
}

static void FreeMemNode(ListNode** node)
{
    if (node == NULL || *node == NULL) {
        return;
    }
    ListNode* listNode = *node;
    MemNode* memNode = (MemNode*)(listNode->data);
    if (memNode != NULL) {
        if (memNode->file != NULL) {
            free(memNode->file);
            memNode->file = NULL;
        }
        if (memNode->func != NULL) {
            free(memNode->func);
            memNode->func = NULL;
        }
        memNode->addr = NULL; // 引用其他指针值，不在该处释放内存，只做记录功能。
        free(memNode);
        memNode = NULL;
    }
    free(listNode);
    *node = NULL;
}

int32_t DestroyMemNodeList(void)
{
    List* list = g_memNodeList;
    if (list == NULL) {
        return ATTEST_OK;
    }
    ListNode* head = list->head;
    while (head != NULL) {
        ListNode* curr = head;
        head = head->next;
        FreeMemNode(&curr);
    }
    free(g_memNodeList);
    g_memNodeList = NULL;
    return ATTEST_OK;
}

static int32_t AddMemNode(List *list, void *data)
{
    if (list == NULL || data == NULL) {
        return ATTEST_ERR;
    }

    ListNode* node = (ListNode *)malloc(sizeof(ListNode));
    if (node == NULL) {
        return ATTEST_ERR;
    }
    node->data = data;
    node->next = NULL;

    ListNode* head = list->head;
    if (head == NULL) {
        list->head = node;
    } else {
        uint32_t size = 1;
        while (head->next != NULL) {
            head = head->next;
            size++;
        }
        if (size >= MAX_MEM_NODE_LIST_LENGTH) {
            free(node);
            node = NULL;
            return ATTEST_ERR;
        }
        head->next = node;
    }
    return ATTEST_OK;
}

static char* StrdupMemInfo(const char* input)
{
    if (input == NULL) {
        return NULL;
    }
    size_t len = strlen(input) + 1;
    if (len == 1) {
        return NULL;
    }
    char* out = malloc(len);
    if (out == NULL) {
        return NULL;
    }
    (void)memset_s(out, len, 0, len);
    if (memcpy_s(out, len, input, strlen(input)) != 0) {
        free(out);
        return NULL;
    }
    return out;
}

int32_t AddMemInfo(void* addr, const char* file, uint32_t line, const char* func)
{
    if (addr == NULL || file == NULL || func == NULL) {
        ATTEST_LOG_ERROR("[AddMemInfo] Parameter is null");
        return ATTEST_ERR;
    }
    MemNode* memNode = (MemNode *)malloc(sizeof(MemNode));
    if (memNode == NULL) {
        return ATTEST_ERR;
    }
    char *memfile = StrdupMemInfo(file);
    char *memfunc = StrdupMemInfo(func);
    memNode->addr = addr;
    memNode->file = memfile;
    memNode->line = line;
    memNode->func = memfunc;
    int32_t ret = AddMemNode(g_memNodeList, memNode);
    if (ret != ATTEST_OK) {
        free(memfile);
        free(memfunc);
        free(memNode);
        ATTEST_LOG_ERROR("[AddMemInfo] Add mem node failed, ret = %d.", ret);
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}

int32_t RemoveMemInfo(const void* addr)
{
    if (addr == NULL) {
        ATTEST_LOG_ERROR("[RemoveMemInfo] addr is null.");
        return ATTEST_ERR;
    }
    List* list = g_memNodeList;
    if (list == NULL) {
        ATTEST_LOG_ERROR("[RemoveMemInfo] g_memNodeList is null");
        return ATTEST_ERR;
    }
    ListNode* curr = list->head;
    ListNode* pre = curr;
    MemNode* data = NULL;
    while (curr != NULL) {
        data = (MemNode *)(curr->data);
        if (data == NULL) {
            ATTEST_LOG_ERROR("[RemoveMemInfo] Data is null.");
            pre = curr;
            curr = curr->next;
            continue;
        }
        if (addr == data->addr) {
            break;
        }
        pre = curr;
        curr = curr->next;
    }
    if (curr == NULL) {
        ATTEST_LOG_ERROR("[RemoveMemInfo] curr is null.");
        return ATTEST_OK;
    }
    if (curr == list->head) {
        list->head = curr->next;
    } else {
        pre->next = curr->next;
    }
    FreeMemNode(&curr);
    return ATTEST_OK;
}

static void PrintMemNode(MemNode *data)
{
    if (data == NULL) {
        ATTEST_LOG_ERROR("[PrintMemNode] data is null.");
        return;
    }
    ATTEST_LOG_INFO("Addr = %p, Func = %s, File = %s, Line = %d.",
        data->addr, data->func, data->file, data->line);
}

void PrintMemNodeList(void)
{
    List* list = g_memNodeList;
    ATTEST_LOG_DEBUG("[PrintMemNodeList] ---Print mem node list begin.---");
    if (list == NULL) {
        ATTEST_LOG_ERROR("[PrintMemNodeList] g_memNodeList is null.");
        return;
    }
    ListNode* head = list->head;
    if (head == NULL) {
        ATTEST_LOG_ERROR("[PrintMemNodeList] No memory leak.");
    } else {
        ATTEST_LOG_INFO("[PrintMemNodeList] Memory leak info:");
    }
    while (head != NULL) {
        PrintMemNode((MemNode *)(head->data));
        head = head->next;
    }
    ATTEST_LOG_DEBUG("[PrintMemNodeList] ---Print mem node list end.---");
}
