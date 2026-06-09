<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import { h, onMounted, ref } from 'vue';

import {
  NButton,
  NCard,
  NDataTable,
  NDrawer,
  NDrawerContent,
  NInput,
  NPopconfirm,
  NSpace,
  NTag,
  useMessage,
} from 'naive-ui';

import {
  deleteVulnKnowledge,
  getVulnKnowledgeList,
  updateVulnKnowledge,
  type VulnKnowledgeItem,
} from '#/api/task';

defineOptions({ name: 'VulnKnowledge' });

const message = useMessage();
const loading = ref(false);
const data = ref<VulnKnowledgeItem[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');

const drawerVisible = ref(false);
const editItem = ref<VulnKnowledgeItem | null>(null);
const editForm = ref({ description: '', cause: '', remediation: '' });
const saving = ref(false);

const columns: DataTableColumns<VulnKnowledgeItem> = [
  {
    title: '漏洞标题',
    key: 'title',
    width: 260,
    ellipsis: { tooltip: true },
  },
  {
    title: 'CVE',
    key: 'cve_id',
    width: 150,
    render(row) {
      return row.cve_id
        ? h(NTag, { size: 'small', type: 'info', bordered: false }, () => row.cve_id)
        : h('span', { style: 'color:#999' }, '-');
    },
  },
  {
    title: '漏洞类型',
    key: 'vuln_type',
    width: 120,
    render(row) {
      return h(NTag, { size: 'small', bordered: false }, () => row.vuln_type || '-');
    },
  },
  {
    title: '漏洞描述',
    key: 'description',
    ellipsis: { tooltip: true },
  },
  {
    title: '命中次数',
    key: 'hit_count',
    width: 90,
    sorter: 'default',
    render(row) {
      return h(NTag, { size: 'small', type: row.hit_count > 5 ? 'warning' : 'default', bordered: false }, () => `${row.hit_count}`);
    },
  },
  {
    title: '更新时间',
    key: 'updated_at',
    width: 170,
    render(row) {
      return new Date(row.updated_at).toLocaleString('zh-CN');
    },
  },
  {
    title: '操作',
    key: 'actions',
    width: 140,
    render(row) {
      return h(NSpace, { size: 4 }, () => [
        h(
          NButton,
          {
            size: 'small',
            quaternary: true,
            type: 'primary',
            onClick: () => openEdit(row),
          },
          () => '查看/编辑',
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleDelete(row.id) },
          {
            trigger: () =>
              h(NButton, { size: 'small', quaternary: true, type: 'error' }, () => '删除'),
            default: () => '确认删除该漏洞知识？',
          },
        ),
      ]);
    },
  },
];

async function fetchData() {
  loading.value = true;
  try {
    const res = await getVulnKnowledgeList({
      page: page.value,
      page_size: pageSize.value,
      keyword: keyword.value || undefined,
    });
    data.value = res.list;
    total.value = res.total;
  } catch {
    message.error('加载漏洞知识失败');
  } finally {
    loading.value = false;
  }
}

function handlePageChange(p: number) {
  page.value = p;
  fetchData();
}

function handlePageSizeChange(ps: number) {
  pageSize.value = ps;
  page.value = 1;
  fetchData();
}

function handleSearch() {
  page.value = 1;
  fetchData();
}

async function handleDelete(id: string) {
  try {
    await deleteVulnKnowledge(id);
    message.success('删除成功');
    await fetchData();
  } catch {
    message.error('删除失败');
  }
}

function openEdit(item: VulnKnowledgeItem) {
  editItem.value = item;
  editForm.value = {
    description: item.description,
    cause: item.cause,
    remediation: item.remediation,
  };
  drawerVisible.value = true;
}

async function handleSave() {
  if (!editItem.value) return;
  saving.value = true;
  try {
    await updateVulnKnowledge(editItem.value.id, editForm.value);
    message.success('保存成功');
    drawerVisible.value = false;
    await fetchData();
  } catch {
    message.error('保存失败');
  } finally {
    saving.value = false;
  }
}

onMounted(fetchData);
</script>

<template>
  <div class="p-4">
    <NCard title="漏洞知识库" size="small">
      <template #header-extra>
        <NSpace>
          <NInput
            v-model:value="keyword"
            placeholder="搜索标题/CVE/描述"
            clearable
            style="width: 260px"
            @keyup.enter="handleSearch"
            @clear="handleSearch"
          />
          <NButton type="primary" size="small" @click="handleSearch">搜索</NButton>
        </NSpace>
      </template>

      <NDataTable
        :columns="columns"
        :data="data"
        :loading="loading"
        :pagination="{
          page,
          pageSize,
          pageCount: Math.ceil(total / pageSize),
          showSizePicker: true,
          pageSizes: [10, 20, 50],
          onChange: handlePageChange,
          onUpdatePageSize: handlePageSizeChange,
          prefix: () => `共 ${total} 条`,
        }"
        :row-key="(row: VulnKnowledgeItem) => row.id"
        striped
        size="small"
        :scroll-x="1000"
      />
    </NCard>

    <NDrawer v-model:show="drawerVisible" :width="600">
      <NDrawerContent :title="editItem?.title || '漏洞知识详情'" closable>
        <div v-if="editItem" class="space-y-4">
          <div class="flex gap-2 mb-4">
            <NTag v-if="editItem.cve_id" size="small" type="info">{{ editItem.cve_id }}</NTag>
            <NTag size="small">{{ editItem.vuln_type }}</NTag>
            <NTag size="small" :bordered="false" type="warning">命中 {{ editItem.hit_count }} 次</NTag>
          </div>

          <div>
            <div class="text-sm font-medium mb-1">漏洞描述</div>
            <NInput
              v-model:value="editForm.description"
              type="textarea"
              :autosize="{ minRows: 3, maxRows: 8 }"
              placeholder="漏洞描述"
            />
          </div>

          <div>
            <div class="text-sm font-medium mb-1">漏洞成因</div>
            <NInput
              v-model:value="editForm.cause"
              type="textarea"
              :autosize="{ minRows: 3, maxRows: 8 }"
              placeholder="漏洞成因"
            />
          </div>

          <div>
            <div class="text-sm font-medium mb-1">修复建议</div>
            <NInput
              v-model:value="editForm.remediation"
              type="textarea"
              :autosize="{ minRows: 3, maxRows: 8 }"
              placeholder="修复建议"
            />
          </div>
        </div>

        <template #footer>
          <NSpace>
            <NButton @click="drawerVisible = false">取消</NButton>
            <NButton type="primary" :loading="saving" @click="handleSave">保存修改</NButton>
          </NSpace>
        </template>
      </NDrawerContent>
    </NDrawer>
  </div>
</template>
