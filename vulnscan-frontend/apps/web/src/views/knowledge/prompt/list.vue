<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import { computed, h, onMounted, ref } from 'vue';

import {
  NButton,
  NCard,
  NDataTable,
  NDrawer,
  NDrawerContent,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NPopconfirm,
  NSelect,
  NSpace,
  NSwitch,
  NTag,
  useMessage,
} from 'naive-ui';

import { useUserStore } from '@vben/stores';

import {
  createPrompt,
  deletePrompt,
  getPromptList,
  SCENE_MAP,
  SCENE_OPTIONS,
  togglePrompt,
  type PromptTemplate,
  updatePrompt,
} from '#/api/prompt/index';
import { useNaiveTablePagination } from '#/composables/useNaiveTablePagination';
import { usePerm } from '#/composables/usePerm';
import { useRoutePerm } from '#/composables/use-route-perm';
import { isAdminRole } from '#/permissions/admin-role';

defineOptions({ name: 'PromptManage' });

const { can, isSuper } = usePerm();
const { perm } = useRoutePerm('/knowledge/prompt');
const userStore = useUserStore();
const isAdmin = computed(() => isAdminRole(userStore.userRoles as string[] | undefined));

function hasPerm(action: string): boolean {
  if (isSuper.value || isAdmin.value) return true;
  return can(perm(action));
}
const message = useMessage();
const loading = ref(false);
const data = ref<PromptTemplate[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const sceneFilter = ref<null | string>(null);

const showEditor = ref(false);
const editorMode = ref<'create' | 'edit'>('create');
const editId = ref('');
const formData = ref<Partial<PromptTemplate>>({});

async function fetchData() {
  loading.value = true;
  try {
    const res = await getPromptList({
      page: page.value,
      page_size: pageSize.value,
      keyword: keyword.value || undefined,
      scene: sceneFilter.value || undefined,
    });
    data.value = res.list;
    total.value = res.total;
  } finally {
    loading.value = false;
  }
}

const { pagination } = useNaiveTablePagination({ page, pageSize, total, onFetch: fetchData });

function openCreate() {
  editorMode.value = 'create';
  editId.value = '';
  formData.value = {
    name: '',
    scene: 'custom',
    description: '',
    system_prompt: '',
    user_prompt: '',
    output_format: '',
    variables: '[]',
    model_name: '',
    temperature: 0.3,
    max_tokens: 2000,
  };
  showEditor.value = true;
}

function openEdit(row: PromptTemplate) {
  editorMode.value = 'edit';
  editId.value = row.id;
  formData.value = { ...row };
  showEditor.value = true;
}

async function handleSave() {
  try {
    if (editorMode.value === 'create') {
      await createPrompt(formData.value);
      message.success('创建成功');
    } else {
      await updatePrompt(editId.value, formData.value);
      message.success('更新成功');
    }
    showEditor.value = false;
    fetchData();
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  }
}

async function handleDelete(id: string) {
  try {
    await deletePrompt(id);
    message.success('已删除');
    fetchData();
  } catch (e: any) {
    message.error(e?.message || '删除失败');
  }
}

async function handleToggle(row: PromptTemplate) {
  try {
    await togglePrompt(row.id);
    message.success(row.enabled ? '已禁用' : '已启用');
    fetchData();
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  }
}

const sceneColor: Record<string, string> = {
  ai_preaudit: 'error',
  ai_classify: 'info',
  intel_analysis: 'warning',
  custom: 'default',
};

const columns: DataTableColumns<PromptTemplate> = [
  {
    title: '模板名称',
    key: 'name',
    width: 180,
    ellipsis: { tooltip: true },
  },
  {
    title: '使用场景',
    key: 'scene',
    width: 130,
    render: (row) =>
      h(
        NTag,
        { size: 'small', type: (sceneColor[row.scene] as any) || 'default' },
        () => SCENE_MAP[row.scene] || row.scene,
      ),
  },
  {
    title: '说明',
    key: 'description',
    ellipsis: { tooltip: true },
  },
  {
    title: '模型',
    key: 'model_name',
    width: 120,
    render: (row) => row.model_name || '自动',
  },
  {
    title: '温度',
    key: 'temperature',
    width: 70,
  },
  {
    title: '版本',
    key: 'version',
    width: 60,
    render: (row) => `v${row.version}`,
  },
  {
    title: '状态',
    key: 'enabled',
    width: 80,
    render: (row) =>
      h(NSwitch, {
        value: row.enabled,
        disabled: !hasPerm('update'),
        onUpdateValue: () => handleToggle(row),
        size: 'small',
      }),
  },
  {
    title: '类型',
    key: 'is_builtin',
    width: 70,
    render: (row) =>
      h(
        NTag,
        { size: 'tiny', type: row.is_builtin ? 'success' : 'default', bordered: false },
        () => (row.is_builtin ? '内置' : '自定义'),
      ),
  },
  {
    title: '操作',
    key: 'actions',
    width: 150,
    fixed: 'right',
    render: (row) =>
      h(NSpace, { size: 4 }, () => [
        hasPerm('update') &&
          h(
            NButton,
            { size: 'tiny', quaternary: true, type: 'primary', onClick: () => openEdit(row) },
            () => '编辑',
          ),
        hasPerm('delete') &&
          !row.is_builtin &&
          h(
            NPopconfirm,
            { onPositiveClick: () => handleDelete(row.id) },
            {
              trigger: () =>
                h(NButton, { size: 'tiny', quaternary: true, type: 'error' }, () => '删除'),
              default: () => '确定删除此模板？',
            },
          ),
      ]),
  },
];

onMounted(fetchData);
</script>

<template>
  <div style="padding: 16px">
    <NCard title="提示模板" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NInput
            v-model:value="keyword"
            placeholder="搜索模板名称..."
            clearable
            size="small"
            style="width: 200px"
            @clear="fetchData"
            @keyup.enter="fetchData"
          />
          <NSelect
            v-model:value="sceneFilter"
            :options="[{ label: '全部场景', value: null as any }, ...SCENE_OPTIONS]"
            size="small"
            style="width: 140px"
            @update:value="fetchData"
          />
          <NButton
            v-if="hasPerm('create')"
            type="primary"
            size="small"
            @click="openCreate"
          >
            新建模板
          </NButton>
        </NSpace>
      </template>

      <NDataTable
        :columns="columns"
        :data="data"
        :loading="loading"
        :pagination="pagination"
        :scroll-x="900"
        size="small"
        striped
        remote
      />
    </NCard>

    <NDrawer v-model:show="showEditor" :width="680" placement="right">
      <NDrawerContent
        :title="editorMode === 'create' ? '新建提示模板' : '编辑提示模板'"
        closable
      >
        <NForm label-placement="top" :model="formData">
          <NFormItem label="模板名称" required>
            <NInput v-model:value="formData.name" placeholder="如：安全事件AI预审" />
          </NFormItem>

          <NFormItem label="使用场景" required>
            <NSelect v-model:value="formData.scene" :options="SCENE_OPTIONS" />
          </NFormItem>

          <NFormItem label="用途说明">
            <NInput
              v-model:value="formData.description"
              type="textarea"
              :rows="2"
              placeholder="描述该模板的用途"
            />
          </NFormItem>

          <NFormItem label="系统提示词 (System Prompt)" required>
            <NInput
              v-model:value="formData.system_prompt"
              type="textarea"
              :rows="4"
              placeholder="定义 AI 的角色和输出要求"
              style="font-family: monospace; font-size: 13px"
            />
          </NFormItem>

          <NFormItem label="用户提示词模板 (User Prompt)" required>
            <NInput
              v-model:value="formData.user_prompt"
              type="textarea"
              :rows="12"
              placeholder="支持模板变量 {{.Name}}、{{.Level}} 等&#10;使用 {{if .CveId}}...{{end}} 条件块"
              style="font-family: monospace; font-size: 13px"
            />
          </NFormItem>

          <NFormItem label="期望输出格式">
            <NInput
              v-model:value="formData.output_format"
              type="textarea"
              :rows="3"
              placeholder='如 {"vuln_desc":"string","vuln_harm":"string"}'
              style="font-family: monospace; font-size: 13px"
            />
          </NFormItem>

          <NFormItem label="可用模板变量 (JSON数组)">
            <NInput
              v-model:value="formData.variables"
              type="textarea"
              :rows="2"
              placeholder='["Name","Level","RiskScore","CveId",...]'
              style="font-family: monospace; font-size: 13px"
            />
          </NFormItem>

          <NSpace :size="16">
            <NFormItem label="指定模型" style="width: 200px">
              <NInput
                v-model:value="formData.model_name"
                placeholder="留空=自动选择"
              />
            </NFormItem>

            <NFormItem label="温度" style="width: 120px">
              <NInputNumber
                v-model:value="formData.temperature"
                :min="0"
                :max="2"
                :step="0.1"
              />
            </NFormItem>

            <NFormItem label="最大Token" style="width: 140px">
              <NInputNumber
                v-model:value="formData.max_tokens"
                :min="100"
                :max="16000"
                :step="100"
              />
            </NFormItem>
          </NSpace>
        </NForm>

        <template #footer>
          <NSpace justify="end">
            <NButton @click="showEditor = false">取消</NButton>
            <NButton type="primary" @click="handleSave">
              {{ editorMode === 'create' ? '创建' : '保存' }}
            </NButton>
          </NSpace>
        </template>
      </NDrawerContent>
    </NDrawer>
  </div>
</template>
