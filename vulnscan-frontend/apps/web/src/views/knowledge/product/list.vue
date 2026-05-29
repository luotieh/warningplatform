<script lang="ts" setup>
import type { DataTableColumns } from "naive-ui";
import { computed, h, onMounted, ref } from "vue";
import {
  NButton,
  NCard,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NDrawer,
  NDrawerContent,
  NForm,
  NFormItem,
  NInput,
  NInputGroup,
  NPopconfirm,
  NSelect,
  NSpace,
  NTag,
  NText,
  useMessage,
} from "naive-ui";
import {
  backfillProducts,
  createProduct,
  deleteProduct,
  getProductList,
  updateProduct,
  type Product,
} from "#/api/product/index";

const message = useMessage();
const loading = ref(false);
const data = ref<Product[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref("");

const showDrawer = ref(false);
const drawerMode = ref<"create" | "edit" | "detail">("create");
const editingItem = ref<Product | null>(null);

const formData = ref<Partial<Product>>({
  name: "",
  vendor: "",
  category: "",
  description: "",
  homepage: "",
  cpe_prefix: "",
  aliases: [],
});

const categoryOptions = [
  { label: "Web 服务器", value: "web-server" },
  { label: "CMS", value: "cms" },
  { label: "开发框架", value: "framework" },
  { label: "数据库", value: "database" },
  { label: "编程语言", value: "language" },
  { label: "JS 框架", value: "js-framework" },
  { label: "JS 库", value: "js-library" },
  { label: "CI/CD", value: "ci-cd" },
  { label: "容器", value: "container" },
  { label: "监控", value: "monitor" },
  { label: "微服务", value: "microservice" },
  { label: "邮件", value: "mail" },
  { label: "VPN", value: "vpn" },
  { label: "防火墙", value: "firewall" },
  { label: "其他", value: "other" },
];

const categoryMap: Record<string, string> = {};
categoryOptions.forEach((o) => {
  categoryMap[o.value] = o.label;
});

async function fetchData() {
  loading.value = true;
  try {
    const res = await getProductList({
      page: page.value,
      page_size: pageSize.value,
      keyword: keyword.value || undefined,
    });
    data.value = res.items;
    total.value = res.total;
  } finally {
    loading.value = false;
  }
}

function handlePageChange(p: number) {
  page.value = p;
  fetchData();
}

function handleSearch() {
  page.value = 1;
  fetchData();
}

function openCreate() {
  drawerMode.value = "create";
  formData.value = { name: "", vendor: "", category: "", description: "", homepage: "", cpe_prefix: "", aliases: [] };
  editingItem.value = null;
  showDrawer.value = true;
}

function openEdit(row: Product) {
  drawerMode.value = "edit";
  editingItem.value = row;
  formData.value = {
    name: row.name,
    vendor: row.vendor,
    category: row.category,
    description: row.description,
    homepage: row.homepage,
    cpe_prefix: row.cpe_prefix,
    aliases: row.aliases || [],
  };
  showDrawer.value = true;
}

function openDetail(row: Product) {
  drawerMode.value = "detail";
  editingItem.value = row;
  showDrawer.value = true;
}

async function handleSave() {
  if (drawerMode.value === "create") {
    try {
      await createProduct(formData.value);
      message.success("创建成功");
      showDrawer.value = false;
      fetchData();
    } catch (e: any) {
      message.error(e?.message || "创建失败");
    }
  } else if (drawerMode.value === "edit" && editingItem.value) {
    try {
      await updateProduct(editingItem.value.id, formData.value);
      message.success("更新成功");
      showDrawer.value = false;
      fetchData();
    } catch (e: any) {
      message.error(e?.message || "更新失败");
    }
  }
}

async function handleDelete(row: Product) {
  try {
    await deleteProduct(row.id);
    message.success("删除成功");
    fetchData();
  } catch (e: any) {
    message.error(e?.message || "删除失败");
  }
}

async function handleBackfill() {
  try {
    const res = await backfillProducts();
    message.success(`回填完成：PoC ${res.poc_updated} 条，指纹 ${res.fingerprint_updated} 条`);
  } catch (e: any) {
    message.error(e?.message || "回填失败");
  }
}

const columns = computed<DataTableColumns<Product>>(() => [
  {
    title: "产品名称",
    key: "name",
    width: 160,
    render: (row) =>
      h(
        NButton,
        { text: true, type: "info", onClick: () => openDetail(row) },
        { default: () => row.name },
      ),
  },
  {
    title: "厂商",
    key: "vendor",
    width: 140,
    render: (row) => row.vendor || "-",
  },
  {
    title: "分类",
    key: "category",
    width: 110,
    render: (row) =>
      row.category
        ? h(NTag, { size: "small", bordered: false }, { default: () => categoryMap[row.category] || row.category })
        : "-",
  },
  {
    title: "关联 PoC",
    key: "poc_count",
    width: 90,
    align: "center",
    render: (row) =>
      h(NText, { depth: row.poc_count ? 1 : 3 }, { default: () => String(row.poc_count ?? 0) }),
  },
  {
    title: "关联指纹",
    key: "fingerprint_count",
    width: 90,
    align: "center",
    render: (row) =>
      h(NText, { depth: row.fingerprint_count ? 1 : 3 }, { default: () => String(row.fingerprint_count ?? 0) }),
  },
  {
    title: "关联漏洞",
    key: "vuln_count",
    width: 90,
    align: "center",
    render: (row) =>
      h(NText, { depth: row.vuln_count ? 1 : 3 }, { default: () => String(row.vuln_count ?? 0) }),
  },
  {
    title: "操作",
    key: "actions",
    width: 140,
    render: (row) =>
      h(NSpace, { size: 4 }, {
        default: () => [
          h(NButton, { text: true, type: "info", size: "small", onClick: () => openEdit(row) }, { default: () => "编辑" }),
          h(
            NPopconfirm,
            { onPositiveClick: () => handleDelete(row) },
            {
              trigger: () => h(NButton, { text: true, type: "error", size: "small" }, { default: () => "删除" }),
              default: () => `确定删除「${row.name}」？`,
            },
          ),
        ],
      }),
  },
]);

const drawerTitle = computed(() => {
  if (drawerMode.value === "create") return "新建产品";
  if (drawerMode.value === "edit") return "编辑产品";
  return "产品详情";
});

const aliasesText = computed({
  get: () => (formData.value.aliases || []).join(", "),
  set: (val: string) => {
    formData.value.aliases = val
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  },
});

onMounted(fetchData);
</script>

<template>
  <div class="p-4">
    <NCard title="产品知识库" :bordered="false">
      <template #header-extra>
        <NSpace>
          <NInputGroup>
            <NInput
              v-model:value="keyword"
              placeholder="搜索产品名称 / 厂商"
              clearable
              style="width: 220px"
              @keydown.enter="handleSearch"
            />
            <NButton type="primary" @click="handleSearch">搜索</NButton>
          </NInputGroup>
          <NButton @click="handleBackfill">回填关联</NButton>
          <NButton type="primary" @click="openCreate">新建产品</NButton>
        </NSpace>
      </template>

      <NDataTable
        :columns="columns"
        :data="data"
        :loading="loading"
        :pagination="{
          page: page,
          pageSize: pageSize,
          itemCount: total,
          onChange: handlePageChange,
          showSizePicker: false,
        }"
        :row-key="(row: Product) => row.id"
        size="small"
        striped
      />
    </NCard>

    <NDrawer v-model:show="showDrawer" :width="540">
      <NDrawerContent :title="drawerTitle" closable>
        <template v-if="drawerMode === 'detail' && editingItem">
          <NDescriptions :column="1" label-placement="left" bordered size="small">
            <NDescriptionsItem label="名称">{{ editingItem.name }}</NDescriptionsItem>
            <NDescriptionsItem label="厂商">{{ editingItem.vendor || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="分类">
              {{ categoryMap[editingItem.category] || editingItem.category || '-' }}
            </NDescriptionsItem>
            <NDescriptionsItem label="CPE 前缀">{{ editingItem.cpe_prefix || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="主页">
              <a v-if="editingItem.homepage" :href="editingItem.homepage" target="_blank" rel="noopener">
                {{ editingItem.homepage }}
              </a>
              <span v-else>-</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="别名">
              <template v-if="editingItem.aliases?.length">
                <NTag v-for="a in editingItem.aliases" :key="a" size="small" style="margin: 2px">{{ a }}</NTag>
              </template>
              <span v-else>-</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="关联 PoC">{{ editingItem.poc_count ?? 0 }}</NDescriptionsItem>
            <NDescriptionsItem label="关联指纹">{{ editingItem.fingerprint_count ?? 0 }}</NDescriptionsItem>
            <NDescriptionsItem label="关联漏洞">{{ editingItem.vuln_count ?? 0 }}</NDescriptionsItem>
          </NDescriptions>
          <div v-if="editingItem.description" style="margin-top: 16px">
            <NText strong>产品简介</NText>
            <div style="margin-top: 8px; line-height: 1.7; color: var(--text-color-2)">
              {{ editingItem.description }}
            </div>
          </div>
        </template>

        <template v-else>
          <NForm label-placement="left" label-width="80">
            <NFormItem label="名称" required>
              <NInput v-model:value="formData.name" placeholder="产品名称（小写规范名）" />
            </NFormItem>
            <NFormItem label="厂商">
              <NInput v-model:value="formData.vendor" placeholder="厂商 / 开发组织" />
            </NFormItem>
            <NFormItem label="分类">
              <NSelect v-model:value="formData.category" :options="categoryOptions" clearable placeholder="选择分类" />
            </NFormItem>
            <NFormItem label="简介">
              <NInput v-model:value="formData.description" type="textarea" :rows="4" placeholder="用于报告的产品描述" />
            </NFormItem>
            <NFormItem label="主页">
              <NInput v-model:value="formData.homepage" placeholder="https://..." />
            </NFormItem>
            <NFormItem label="CPE 前缀">
              <NInput v-model:value="formData.cpe_prefix" placeholder="cpe:2.3:a:vendor:product" />
            </NFormItem>
            <NFormItem label="别名">
              <NInput v-model:value="aliasesText" placeholder="逗号分隔，如：openresty, tengine" />
            </NFormItem>
          </NForm>
          <NSpace justify="end" style="margin-top: 16px">
            <NButton @click="showDrawer = false">取消</NButton>
            <NButton type="primary" @click="handleSave">保存</NButton>
          </NSpace>
        </template>
      </NDrawerContent>
    </NDrawer>
  </div>
</template>
