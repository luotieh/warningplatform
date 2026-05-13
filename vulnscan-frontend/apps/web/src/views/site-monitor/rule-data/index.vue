<script lang="ts" setup>
import type { RuleDataSummary } from '#/api/sitemonitor';

import { onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';

import dayjs from 'dayjs';
import { NButton, NCard, NEmpty, NSpace, NSpin, NTag } from 'naive-ui';

import { message } from '#/adapter/naive';
import {
  getRuleDataList,
  resetDefaultRuleData,
  syncAllRuleData,
} from '#/api/sitemonitor';

defineOptions({ name: 'RuleData' });

const router = useRouter();
const loading = ref(false);
const modules = ref<RuleDataSummary[]>([]);

async function fetchList() {
  loading.value = true;
  try {
    const res = await getRuleDataList();
    modules.value = Array.isArray(res) ? res : ((res as any)?.data || []);
  } catch (e: any) {
    message.error(e?.msg || '获取规则模块列表失败');
  } finally {
    loading.value = false;
  }
}

async function handleSyncAll() {
  try {
    await syncAllRuleData();
    message.success('全量同步已触发');
  } catch (e: any) {
    message.error(e?.msg || '同步失败');
  }
}

async function handleResetDefaults() {
  try {
    await resetDefaultRuleData();
    message.success('默认规则已重置');
    await fetchList();
  } catch (e: any) {
    message.error(e?.msg || '重置失败');
  }
}

function goDetail(moduleKey: string) {
  router.push(`/monitor/rules/rule-data/detail/${moduleKey}`);
}

const typeLabel = (t: string) => (t === 'engine' ? '引擎规则' : '数据字典');
const typeTagType = (t: string): 'primary' | 'success' =>
  t === 'engine' ? 'primary' : 'success';

const fmtTime = (t: string) => (t ? dayjs(t).format('YYYY-MM-DD HH:mm:ss') : '-');

onMounted(() => fetchList());
</script>

<template>
  <Page title="规则数据管理" description="管理后端规则引擎与数据字典模块">
    <template #extra>
      <NSpace>
        <NButton @click="handleResetDefaults">初始化默认规则</NButton>
        <NButton type="warning" @click="handleSyncAll">
          全量同步到 Agent
        </NButton>
        <NButton @click="fetchList">刷新</NButton>
      </NSpace>
    </template>

    <NSpin :show="loading">
      <div class="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        <NCard
          v-for="mod in modules"
          :key="mod.module_key"
          hoverable
          class="cursor-pointer"
          @click="goDetail(mod.module_key)"
        >
          <div class="mb-2 flex items-start justify-between">
            <span class="truncate text-base font-bold">{{ mod.name }}</span>
            <NTag
              :type="typeTagType(mod.type)"
              size="small"
              :bordered="false"
            >
              {{ typeLabel(mod.type) }}
            </NTag>
          </div>
          <p class="text-muted-foreground mb-3 line-clamp-2 text-sm">
            {{ mod.description }}
          </p>
          <div
            class="text-muted-foreground flex items-center justify-between text-xs"
          >
            <NTag
              v-if="mod.has_data"
              type="success"
              size="small"
              :bordered="false"
            >
              已配置
            </NTag>
            <NTag v-else type="default" size="small" :bordered="false">
              未配置
            </NTag>
            <span>{{ fmtTime(mod.updated_at) }}</span>
          </div>
        </NCard>
      </div>

      <NEmpty
        v-if="!loading && modules.length === 0"
        description="暂无规则模块"
        class="mt-8"
      />
    </NSpin>
  </Page>
</template>
