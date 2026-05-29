<script lang="ts" setup>
import type { FileLibrary, RuleDataSummary, WordLibrary } from '#/api/sitemonitor';

import { computed, h, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';
import { IconifyIcon } from '@vben/icons';

import dayjs from 'dayjs';
import {
  NButton,
  NCard,
  NDataTable,
  NDrawer,
  NDrawerContent,
  NEmpty,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NSpace,
  NSpin,
  NTag,
  NTooltip,
} from 'naive-ui';

import { dialog, message } from '#/adapter/naive';
import {
  createFileLibrary,
  createWordCategory,
  createWordLibrary,
  deleteFileLibrary,
  deleteWordLibrary,
  getFileLibraryList,
  getRuleData,
  getRuleDataList,
  getWordLibraryList,
  importRuleData,
  resetDefaultRuleData,
  syncAllRuleData,
  updateFileLibrary,
  updateWordLibrary,
} from '#/api/sitemonitor';

defineOptions({ name: 'RuleEngine' });

const router = useRouter();
const loading = ref(false);
const modules = ref<RuleDataSummary[]>([]);
const searchKeyword = ref('');

const groupMeta: Record<string, { label: string; color: string }> = {
  detect: { label: '检测引擎', color: '#3b82f6' },
  dict: { label: '数据字典', color: '#10b981' },
  common: { label: '公共配置', color: '#8b5cf6' },
  resource: { label: '监测资源库', color: '#f59e0b' },
};
const resourceLabel = '监测资源库';
const resourceColor = '#f59e0b';

const iconMap: Record<string, string> = {
  heartbeat: 'lucide:activity',
  globe: 'lucide:globe',
  shield: 'lucide:shield-check',
  link: 'lucide:link',
  bug: 'lucide:bug',
  file: 'lucide:file-code',
  search: 'lucide:search',
  terminal: 'lucide:terminal',
  settings: 'lucide:settings-2',
  list: 'lucide:list',
  folder: 'lucide:folder',
  database: 'lucide:database',
};

const fallbackIcon = 'lucide:package';

function getModuleIcon(icon?: string) {
  return icon ? iconMap[icon] || fallbackIcon : fallbackIcon;
}

function getModuleColor(groupKey: string) {
  return groupMeta[groupKey]?.color || '#64748b';
}

const filteredModules = computed(() => {
  const kw = searchKeyword.value.toLowerCase().trim();
  if (!kw) return modules.value;
  return modules.value.filter(
    (m) =>
      m.name.toLowerCase().includes(kw) ||
      m.description.toLowerCase().includes(kw) ||
      m.module_key.toLowerCase().includes(kw),
  );
});

const groupedModules = computed(() => {
  const groups: Record<string, RuleDataSummary[]> = {};
  for (const m of filteredModules.value) {
    const g = m.group || 'common';
    if (!groups[g]) groups[g] = [];
    groups[g].push(m);
  }
  return groups;
});

const groupOrder = ['detect', 'resource', 'dict', 'common'];

const wordLibraries = ref<WordLibrary[]>([]);
const fileLibraries = ref<FileLibrary[]>([]);

async function fetchLibraries() {
  try {
    const [wRes, fRes] = await Promise.all([
      getWordLibraryList({ index: 1, size: 100 }),
      getFileLibraryList({ index: 1, size: 100 }),
    ]);
    wordLibraries.value = wRes?.data || [];
    fileLibraries.value = fRes?.data || [];
  } catch {
    /* ignore */
  }
}

const showLibDrawer = ref(false);
const libDrawerType = ref<'file' | 'word'>('word');
const libDrawerTitle = computed(() => libDrawerType.value === 'word' ? '敏感词库管理' : '敏感文件库管理');
const libDrawerList = computed(() => libDrawerType.value === 'word' ? wordLibraries.value : fileLibraries.value);

function openLibDrawer(type: 'file' | 'word') {
  libDrawerType.value = type;
  showLibDrawer.value = true;
}

const showLibFormModal = ref(false);
const libFormTitle = ref('');
const libForm = ref({ id: '', isEdit: false, name: '', description: '' });
const libFormSubmitting = ref(false);

function openLibCreate() {
  const label = libDrawerType.value === 'word' ? '词库' : '文件库';
  libFormTitle.value = `新增${label}`;
  libForm.value = { isEdit: false, id: '', name: '', description: '' };
  showLibFormModal.value = true;
}

function openLibEdit(row: FileLibrary | WordLibrary) {
  const label = libDrawerType.value === 'word' ? '词库' : '文件库';
  libFormTitle.value = `编辑${label}`;
  libForm.value = { isEdit: true, id: row.id, name: row.name, description: row.description };
  showLibFormModal.value = true;
}

async function handleLibFormSubmit() {
  if (!libForm.value.name.trim()) { message.warning('请填写名称'); return; }
  libFormSubmitting.value = true;
  try {
    const payload = { name: libForm.value.name, description: libForm.value.description };
    if (libDrawerType.value === 'word') {
      if (libForm.value.isEdit) {
        await updateWordLibrary(libForm.value.id, payload);
      } else {
        const res = await createWordLibrary(payload);
        const newId = (res as any)?.id ?? (res as any)?.data?.id;
        if (newId) {
          try {
            await createWordCategory({
              library_id: newId,
              name: libForm.value.name.trim(),
              description: '自动创建的默认分类',
            });
          } catch { /* 默认分类创建失败不阻塞主流程 */ }
        }
      }
    } else {
      libForm.value.isEdit ? await updateFileLibrary(libForm.value.id, payload) : await createFileLibrary(payload);
    }
    message.success(libForm.value.isEdit ? '更新成功' : '创建成功');
    showLibFormModal.value = false;
    await fetchLibraries();
  } catch (e: any) { message.error(e?.msg || '操作失败'); }
  finally { libFormSubmitting.value = false; }
}

function handleLibDelete(row: FileLibrary | WordLibrary) {
  const label = libDrawerType.value === 'word' ? '词库' : '文件库';
  dialog.warning({
    title: '提示',
    content: `确认删除${label}「${row.name}」？删除后不可恢复`,
    positiveText: '确认删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        if (libDrawerType.value === 'word') {
          await deleteWordLibrary(row.id);
        } else {
          await deleteFileLibrary(row.id);
        }
        message.success('删除成功');
        await fetchLibraries();
      } catch (e: any) { message.error(e?.msg || '删除失败'); }
    },
  });
}

function goLibDetail(row: FileLibrary | WordLibrary) {
  const prefix = libDrawerType.value === 'word' ? 'word' : 'file';
  router.push(`/knowledge/datalib/${prefix}/${row.id}`);
}

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
  router.push(`/knowledge/rule-engine/detail/${moduleKey}`);
}

async function handleExport(mod: RuleDataSummary) {
  try {
    const res = await getRuleData(mod.module_key);
    const data = (res as any)?.data ?? res;
    const blob = new Blob(
      [typeof data === 'string' ? data : JSON.stringify(data, null, 2)],
      { type: 'application/json' },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${mod.module_key}.json`;
    a.click();
    URL.revokeObjectURL(url);
    message.success(`${mod.name} 已导出`);
  } catch (e: any) {
    message.error(e?.msg || '导出失败');
  }
}

function handleImportClick(mod: RuleDataSummary) {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  input.onchange = async (e: Event) => {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const data = JSON.parse(text);
      await importRuleData(mod.module_key, data, true);
      message.success(`${mod.name} 导入成功`);
      await fetchList();
    } catch (err: any) {
      message.error(err?.msg || '导入失败，请检查文件格式');
    }
  };
  input.click();
}

const fmtTime = (t: string) =>
  t ? dayjs(t).format('YYYY-MM-DD HH:mm') : '-';

onMounted(() => {
  fetchList();
  fetchLibraries();
});
</script>

<template>
  <Page title="规则引擎" description="管理监测规则引擎与数据字典模块">
    <template #extra>
      <NSpace>
        <NInput
          v-model:value="searchKeyword"
          placeholder="搜索模块名称/描述..."
          clearable
          style="width: 220px"
        />
        <NButton @click="handleResetDefaults">初始化默认规则</NButton>
        <NButton type="warning" @click="handleSyncAll">
          全量同步到 Agent
        </NButton>
        <NButton @click="fetchList">刷新</NButton>
      </NSpace>
    </template>

    <NSpin :show="loading">
      <template v-for="groupKey in groupOrder" :key="groupKey">
        <div v-if="groupedModules[groupKey]?.length" class="mb-6">
          <div class="mb-3 flex items-center gap-2">
            <div
              class="h-4 w-1 rounded"
              :style="{ background: groupMeta[groupKey]?.color || '#999' }"
            />
            <span class="text-base font-semibold">
              {{ groupMeta[groupKey]?.label || groupKey }}
            </span>
            <NTag size="small" :bordered="false" round>
              {{ groupedModules[groupKey]?.length }} 个模块
            </NTag>
          </div>

          <div
            class="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4"
          >
            <NCard
              v-for="mod in groupedModules[groupKey]"
              :key="mod.module_key"
              hoverable
              size="small"
              class="module-card cursor-pointer transition-shadow hover:shadow-md"
              @click="goDetail(mod.module_key)"
            >
              <div class="flex items-start gap-3">
                <span
                  class="rule-engine-icon"
                  :style="{
                    backgroundColor: `${getModuleColor(groupKey)}14`,
                    color: getModuleColor(groupKey),
                  }"
                >
                  <IconifyIcon :icon="getModuleIcon(mod.icon)" />
                </span>
                <div class="min-w-0 flex-1">
                  <div class="mb-1 flex items-center justify-between">
                    <span class="truncate text-sm font-bold">
                      {{ mod.name }}
                    </span>
                    <NTag
                      :type="mod.type === 'engine' ? 'primary' : 'success'"
                      size="tiny"
                      :bordered="false"
                    >
                      {{ mod.type === 'engine' ? '引擎' : '字典' }}
                    </NTag>
                  </div>
                  <p
                    class="text-muted-foreground mb-2 line-clamp-2 text-xs leading-relaxed"
                  >
                    {{ mod.description || '暂无描述' }}
                  </p>
                  <div
                    class="flex items-center justify-between text-xs text-gray-400"
                  >
                    <div class="flex items-center gap-2">
                      <NTag
                        v-if="mod.has_data"
                        type="success"
                        size="tiny"
                        :bordered="false"
                      >
                        已配置
                      </NTag>
                      <NTag v-else type="default" size="tiny" :bordered="false">
                        未配置
                      </NTag>
                      <span v-if="mod.rule_count > 0" class="text-gray-500">
                        {{ mod.rule_count }} 条
                      </span>
                    </div>
                    <span>{{ fmtTime(mod.updated_at) }}</span>
                  </div>
                </div>
              </div>

              <div
                class="module-actions mt-2 flex justify-end gap-1 border-t border-gray-100 pt-2"
                @click.stop
              >
                <NTooltip>
                  <template #trigger>
                    <NButton text size="tiny" @click="handleExport(mod)">
                      导出
                    </NButton>
                  </template>
                  导出为 JSON 文件
                </NTooltip>
                <NTooltip>
                  <template #trigger>
                    <NButton text size="tiny" @click="handleImportClick(mod)">
                      导入
                    </NButton>
                  </template>
                  从 JSON 文件导入（合并模式）
                </NTooltip>
              </div>
            </NCard>
          </div>
        </div>
      </template>

      <div
        v-if="!searchKeyword"
        class="mb-6"
      >
        <div class="mb-3 flex items-center gap-2">
          <div
            class="h-4 w-1 rounded"
            :style="{ background: resourceColor }"
          />
          <span class="text-base font-semibold">
            {{ resourceLabel }}
          </span>
        </div>

        <div
          class="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4"
        >
          <NCard
            v-if="wordLibraries.length > 0 || true"
            hoverable
            size="small"
            class="module-card cursor-pointer transition-shadow hover:shadow-md"
            @click="openLibDrawer('word')"
          >
            <div class="flex items-start gap-3">
              <span
                class="rule-engine-icon"
                :style="{
                  backgroundColor: `${resourceColor}14`,
                  color: resourceColor,
                }"
              >
                <IconifyIcon icon="lucide:file-text" />
              </span>
              <div class="min-w-0 flex-1">
                <div class="mb-1 flex items-center justify-between">
                  <span class="truncate text-sm font-bold">敏感词库</span>
                  <NTag type="warning" size="tiny" :bordered="false">
                    资源库
                  </NTag>
                </div>
                <p
                  class="text-muted-foreground mb-2 line-clamp-2 text-xs leading-relaxed"
                >
                  管理敏感词词库和分类，用于敏感词监测维度
                </p>
                <div
                  class="flex items-center justify-between text-xs text-gray-400"
                >
                  <NTag type="success" size="tiny" :bordered="false">
                    {{ wordLibraries.length }} 个词库
                  </NTag>
                </div>
              </div>
            </div>
          </NCard>

          <NCard
            v-if="fileLibraries.length > 0 || true"
            hoverable
            size="small"
            class="module-card cursor-pointer transition-shadow hover:shadow-md"
            @click="openLibDrawer('file')"
          >
            <div class="flex items-start gap-3">
              <span
                class="rule-engine-icon"
                :style="{
                  backgroundColor: `${resourceColor}14`,
                  color: resourceColor,
                }"
              >
                <IconifyIcon icon="lucide:folder" />
              </span>
              <div class="min-w-0 flex-1">
                <div class="mb-1 flex items-center justify-between">
                  <span class="truncate text-sm font-bold">敏感文件库</span>
                  <NTag type="warning" size="tiny" :bordered="false">
                    资源库
                  </NTag>
                </div>
                <p
                  class="text-muted-foreground mb-2 line-clamp-2 text-xs leading-relaxed"
                >
                  管理敏感文件路径库，用于敏感文件监测维度
                </p>
                <div
                  class="flex items-center justify-between text-xs text-gray-400"
                >
                  <NTag type="success" size="tiny" :bordered="false">
                    {{ fileLibraries.length }} 个文件库
                  </NTag>
                </div>
              </div>
            </div>
          </NCard>
        </div>
      </div>

      <NEmpty
        v-if="!loading && filteredModules.length === 0"
        :description="
          searchKeyword ? '未找到匹配的模块' : '暂无规则模块'
        "
        class="mt-8"
      />
    </NSpin>

    <NDrawer v-model:show="showLibDrawer" :width="680">
      <NDrawerContent>
        <template #header>
          <div class="flex w-full items-center justify-between">
            <span>{{ libDrawerTitle }}</span>
            <NButton size="small" type="primary" @click="openLibCreate">
              新增
            </NButton>
          </div>
        </template>

        <NDataTable
          :columns="[
            { key: 'name', title: '名称', minWidth: 120, ellipsis: { tooltip: true } },
            { key: 'description', title: '描述', minWidth: 160, ellipsis: { tooltip: true } },
            { key: 'created_at', title: '创建时间', width: 160, render: (row: any) => row.created_at ? dayjs(row.created_at).format('YYYY-MM-DD HH:mm:ss') : '-' },
            { key: 'op', title: '操作', width: 200, fixed: 'right', render: (row: any) => h(NSpace, { size: 'small' }, () => [
              h(NButton, { text: true, type: 'primary', size: 'small', onClick: () => goLibDetail(row) }, () => '详情'),
              h(NButton, { text: true, type: 'primary', size: 'small', onClick: () => openLibEdit(row) }, () => '编辑'),
              h(NButton, { text: true, type: 'error', size: 'small', onClick: () => handleLibDelete(row) }, () => '删除'),
            ]) },
          ]"
          :data="libDrawerList"
          :bordered="false"
          size="small"
          striped
        />
      </NDrawerContent>
    </NDrawer>

    <NModal v-model:show="showLibFormModal" preset="card" :title="libFormTitle" style="width: 500px">
      <NForm label-placement="left" :label-width="80">
        <NFormItem label="名称" required>
          <NInput v-model:value="libForm.name" placeholder="请输入名称" />
        </NFormItem>
        <NFormItem label="描述">
          <NInput v-model:value="libForm.description" type="textarea" :rows="3" placeholder="请输入描述" />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="showLibFormModal = false">取消</NButton>
          <NButton type="primary" :loading="libFormSubmitting" @click="handleLibFormSubmit">确定</NButton>
        </NSpace>
      </template>
    </NModal>
  </Page>
</template>

<style scoped>
.rule-engine-icon {
  display: inline-flex;
  width: 32px;
  height: 32px;
  flex: 0 0 32px;
  align-items: center;
  justify-content: center;
  border-radius: 8px;
  font-size: 18px;
  line-height: 1;
}

.module-card .module-actions {
  opacity: 0;
  transition: opacity 0.2s;
}
.module-card:hover .module-actions {
  opacity: 1;
}
</style>
