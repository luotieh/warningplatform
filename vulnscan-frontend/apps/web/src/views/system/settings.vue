<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import {
  NCard,
  NTabs,
  NTabPane,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NSwitch,
  NButton,
  NSpace,
  NAlert,
  NPopconfirm,
  NSpin,
  NTag,
  useMessage,
} from 'naive-ui';
import {
  getSettings,
  batchUpdateSettings,
  resetGroup,
  type SystemSetting,
} from '#/api/setting';

const message = useMessage();
const loading = ref(false);
const saving = ref(false);
const allSettings = ref<SystemSetting[]>([]);
const editMap = ref<Record<string, string>>({});

const groups = computed(() => {
  const map = new Map<string, SystemSetting[]>();
  for (const s of allSettings.value) {
    const list = map.get(s.group) || [];
    list.push(s);
    map.set(s.group, list);
  }
  return map;
});

const groupLabels: Record<string, string> = {
  scanner: '扫描引擎',
  scheduler: '任务调度',
  federation: '联邦管理',
  cyberspace: '网络空间测绘',
};

async function loadSettings() {
  loading.value = true;
  try {
    allSettings.value = await getSettings();
    editMap.value = {};
    for (const s of allSettings.value) {
      editMap.value[s.key] = s.is_secret && s.value === '******' ? '' : s.value;
    }
  } catch {
    message.error('加载设置失败');
  } finally {
    loading.value = false;
  }
}

async function saveGroup(group: string) {
  const items = allSettings.value
    .filter((s) => s.group === group)
    .filter((s) => {
      if (s.is_secret && editMap.value[s.key] === '') return false;
      return editMap.value[s.key] !== s.value;
    })
    .map((s) => ({ key: s.key, value: editMap.value[s.key] ?? '' }));

  if (items.length === 0) {
    message.info('没有需要保存的更改');
    return;
  }

  saving.value = true;
  try {
    await batchUpdateSettings(items);
    message.success(`已保存 ${items.length} 项设置`);
    await loadSettings();
  } catch {
    message.error('保存失败');
  } finally {
    saving.value = false;
  }
}

async function onReset(group: string) {
  try {
    await resetGroup(group);
    message.success('已重置为默认值');
    await loadSettings();
  } catch {
    message.error('重置失败');
  }
}

function renderInput(item: SystemSetting) {
  return { item };
}

onMounted(loadSettings);
</script>

<template>
  <div class="p-4">
    <NCard title="系统设置" size="small">
      <template #header-extra>
        <NButton size="small" @click="loadSettings">
          刷新
        </NButton>
      </template>

      <NAlert type="info" :bordered="false" class="mb-4">
        以下配置保存在数据库中，修改后立即生效（部分配置需重启服务）。敏感字段显示为 ****** ，留空则不更新。
      </NAlert>

      <NSpin :show="loading">
        <NTabs type="line" animated>
          <NTabPane
            v-for="[group, items] in groups"
            :key="group"
            :name="group"
            :tab="groupLabels[group] || group"
          >
            <NForm label-placement="left" label-width="180" class="max-w-2xl">
              <NFormItem
                v-for="item in items"
                :key="item.key"
                :label="item.label || item.key"
              >
                <template #label>
                  <div>
                    <span>{{ item.label || item.key }}</span>
                    <NTag
                      v-if="item.is_secret"
                      size="tiny"
                      type="warning"
                      class="ml-2"
                    >
                      敏感
                    </NTag>
                  </div>
                </template>

                <NSwitch
                  v-if="item.value_type === 'bool'"
                  :value="editMap[item.key] === 'true'"
                  @update:value="(v: boolean) => (editMap[item.key] = String(v))"
                />
                <NInputNumber
                  v-else-if="item.value_type === 'int'"
                  :value="Number(editMap[item.key]) || 0"
                  class="w-full"
                  @update:value="(v: number | null) => (editMap[item.key] = String(v ?? 0))"
                />
                <NInput
                  v-else
                  v-model:value="editMap[item.key]"
                  :type="item.is_secret ? 'password' : 'text'"
                  :placeholder="item.description || item.key"
                  show-password-on="click"
                />

                <template v-if="item.description && item.value_type !== 'bool'" #feedback>
                  <span class="text-xs text-gray-400">{{ item.description }}</span>
                </template>
              </NFormItem>
            </NForm>

            <NSpace class="mt-4">
              <NButton
                type="primary"
                :loading="saving"
                @click="saveGroup(group)"
              >
                保存
              </NButton>
              <NPopconfirm @positive-click="() => onReset(group)">
                <template #trigger>
                  <NButton>恢复默认</NButton>
                </template>
                确认将「{{ groupLabels[group] || group }}」的所有设置恢复为默认值？
              </NPopconfirm>
            </NSpace>
          </NTabPane>
        </NTabs>
      </NSpin>
    </NCard>
  </div>
</template>
