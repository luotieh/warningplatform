<script lang="ts" setup>
import { computed, h, onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';

import {
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPagination,
  NSelect,
  NSpace,
  NTag,
  NUpload,
} from 'naive-ui';

import { dialog, message } from '#/adapter/naive';
import {
  lyAssetCreate,
  lyAssetDelete,
  lyAssetImport,
  lyAssetList,
  lyAssetTemplateUrl,
  lyAssetUpdate,
  type LyAsset,
} from '#/api/ly/assets';
import { useLyStore } from '#/store/ly';
import { countAssetEvents } from '#/utils/ly-asset';
import { paginate } from '#/utils/ly';

defineOptions({ name: 'LyAssets' });

const router = useRouter();
const lyStore = useLyStore();

const assets = ref<LyAsset[]>([]);
const loading = ref(false);
const state = reactive({ keyword: '', type: '', status: '', page: 1, pageSize: 10 });

const typeOptions = [
  { label: 'IP资产', value: 'ip' },
  { label: '域名网站', value: 'domain_site' },
];
const statusOptions = [
  { label: '启用', value: '1' },
  { label: '停用', value: '0' },
];

const filtered = computed(() =>
  assets.value.filter((a) => {
    if (state.type && a.asset_type !== state.type) return false;
    if (state.status !== '' && String(a.status ?? 1) !== state.status) return false;
    if (state.keyword) {
      const k = state.keyword.toLowerCase();
      if (!String(a.name).toLowerCase().includes(k) && !String(a.address).toLowerCase().includes(k)) return false;
    }
    return true;
  }),
);
const paged = computed(() => paginate(filtered.value, state.page, state.pageSize));

async function load() {
  loading.value = true;
  try {
    assets.value = (await lyAssetList()) || [];
    if (!lyStore.events.length) await lyStore.loadEvents();
  } catch (error) {
    message.error(error instanceof Error ? error.message : '加载失败');
  } finally {
    loading.value = false;
  }
}

// 新增/编辑
const editVisible = ref(false);
const editing = ref(false);
const form = reactive<LyAsset>({ name: '', asset_type: 'ip', address: '', unit: '', owner: '', remark: '', status: 1 });
let editId = '';

function openCreate() {
  editing.value = false;
  editId = '';
  Object.assign(form, { name: '', asset_type: 'ip', address: '', unit: '', owner: '', remark: '', status: 1 });
  editVisible.value = true;
}
function openEdit(row: LyAsset) {
  editing.value = true;
  editId = String(row.id);
  Object.assign(form, { ...row });
  editVisible.value = true;
}
async function submit() {
  if (!form.name.trim() || !form.address.trim()) {
    message.error('资产名称与地址必填');
    return;
  }
  try {
    if (editing.value) {
      await lyAssetUpdate(editId, { ...form });
      message.success('已更新');
    } else {
      await lyAssetCreate({ ...form });
      message.success('已创建');
    }
    editVisible.value = false;
    await load();
  } catch (error) {
    message.error(error instanceof Error ? error.message : '保存失败');
  }
}
function remove(row: LyAsset) {
  dialog.warning({
    title: '删除资产',
    content: `确认删除资产「${row.name}（${row.address}）」？`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await lyAssetDelete(String(row.id));
        message.success('已删除');
        await load();
      } catch (error) {
        message.error(error instanceof Error ? error.message : '删除失败');
      }
    },
  });
}

// 导入
const importVisible = ref(false);
const importResult = ref<{ imported: number; errors: Array<{ row: number; message: string }> } | null>(null);
async function onUpload({ file }: { file: { file?: File | null } }) {
  if (!file.file) return;
  try {
    importResult.value = await lyAssetImport(file.file);
    message.success(`导入成功 ${importResult.value.imported} 条`);
    await load();
  } catch (error) {
    message.error(error instanceof Error ? error.message : '导入失败');
  }
}

function jumpToEvents(row: LyAsset) {
  router.push({ path: '/ly/event/list', query: { asset: row.address } });
}

const columns = [
  { title: '名称', key: 'name', minWidth: 140 },
  {
    title: '类型',
    key: 'asset_type',
    width: 110,
    render: (row: LyAsset) =>
      h(NTag, { size: 'small', type: row.asset_type === 'ip' ? 'info' : 'warning' }, { default: () => (row.asset_type === 'ip' ? 'IP资产' : '域名网站') }),
  },
  { title: '地址', key: 'address', minWidth: 160 },
  { title: '所属单位', key: 'unit', minWidth: 120 },
  { title: '责任人', key: 'owner', width: 100 },
  {
    title: '状态',
    key: 'status',
    width: 90,
    render: (row: LyAsset) =>
      h(NTag, { size: 'small', type: (row.status ?? 1) === 1 ? 'success' : 'default' }, { default: () => ((row.status ?? 1) === 1 ? '启用' : '停用') }),
  },
  {
    title: '关联事件数',
    key: 'related',
    width: 110,
    render: (row: LyAsset) => {
      const n = countAssetEvents(row, lyStore.events || []);
      return h(NButton, { text: true, type: 'primary', disabled: n === 0, onClick: () => jumpToEvents(row) }, { default: () => String(n) });
    },
  },
  {
    title: '操作',
    key: 'actions',
    width: 140,
    render: (row: LyAsset) =>
      h(NSpace, { size: 4 }, {
        default: () => [
          h(NButton, { text: true, type: 'primary', onClick: () => openEdit(row) }, { default: () => '编辑' }),
          h(NButton, { text: true, type: 'error', onClick: () => remove(row) }, { default: () => '删除' }),
        ],
      }),
  },
];

onMounted(load);
</script>

<template>
  <div class="ly-page">
    <NSpace vertical :size="12">
      <NCard size="small">
        <NSpace>
          <NInput v-model:value="state.keyword" clearable placeholder="名称或地址" style="width: 200px" />
          <NSelect v-model:value="state.type" clearable placeholder="类型" :options="typeOptions" style="width: 140px" />
          <NSelect v-model:value="state.status" clearable placeholder="状态" :options="statusOptions" style="width: 120px" />
          <NButton type="primary" @click="openCreate">新增资产</NButton>
          <NButton @click="importVisible = true">导入</NButton>
          <NButton @click="load">刷新</NButton>
        </NSpace>
      </NCard>

      <NCard size="small">
        <NDataTable :columns="columns" :data="paged" :loading="loading" size="small" :bordered="false" />
        <div class="pager-wrap">
          <NPagination v-model:page="state.page" v-model:page-size="state.pageSize" :item-count="filtered.length" show-size-picker :page-sizes="[10, 20, 50]" />
        </div>
      </NCard>
    </NSpace>

    <NModal v-model:show="editVisible" preset="card" :title="editing ? '编辑资产' : '新增资产'" style="width: 520px">
      <NForm label-placement="left" label-width="90">
        <NFormItem label="资产名称" required>
          <NInput v-model:value="form.name" placeholder="资产名称" />
        </NFormItem>
        <NFormItem label="类型" required>
          <NSelect v-model:value="form.asset_type" :options="typeOptions" />
        </NFormItem>
        <NFormItem label="地址" required>
          <NInput v-model:value="form.address" placeholder="IP 或 域名" />
        </NFormItem>
        <NFormItem label="所属单位">
          <NInput v-model:value="form.unit" />
        </NFormItem>
        <NFormItem label="责任人">
          <NInput v-model:value="form.owner" />
        </NFormItem>
        <NFormItem label="状态">
          <NSelect v-model:value="form.status" :options="[{ label: '启用', value: 1 }, { label: '停用', value: 0 }]" />
        </NFormItem>
        <NFormItem label="备注">
          <NInput v-model:value="form.remark" type="textarea" :rows="2" />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="editVisible = false">取消</NButton>
          <NButton type="primary" @click="submit">保存</NButton>
        </NSpace>
      </template>
    </NModal>

    <NModal v-model:show="importVisible" preset="card" title="导入资产" style="width: 520px">
      <NSpace vertical>
        <a :href="lyAssetTemplateUrl()" download>下载导入模板（CSV）</a>
        <NUpload :show-file-list="false" accept=".csv,.xlsx" :custom-request="() => {}" @change="onUpload">
          <NButton>选择文件并导入（.csv/.xlsx）</NButton>
        </NUpload>
        <div v-if="importResult">
          成功导入 {{ importResult.imported }} 条<span v-if="importResult.errors?.length">，失败 {{ importResult.errors.length }} 条：</span>
          <ul v-if="importResult.errors?.length">
            <li v-for="e in importResult.errors" :key="e.row">第 {{ e.row }} 行：{{ e.message }}</li>
          </ul>
        </div>
      </NSpace>
    </NModal>
  </div>
</template>

<style scoped>
.ly-page { padding: 12px; }
.pager-wrap { display: flex; justify-content: flex-end; margin-top: 12px; }
</style>
