<script lang="ts" setup>
import type { DataTableColumns } from "naive-ui";
import { computed, h, onMounted, ref, watch } from "vue";
import {
  NButton,
  NCard,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NDrawer,
  NDrawerContent,
  NEmpty,
  NForm,
  NFormItem,
  NInput,
  NInputGroup,
  NPopconfirm,
  NScrollbar,
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
  getProductSummary,
  reclassifyProducts,
  updateProduct,
  type CategoryGroup,
  type Product,
  type VendorGroup,
} from "#/api/product/index";

const message = useMessage();
const loading = ref(false);
const data = ref<Product[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref("");

const filterVendor = ref<string | null>(null);
const filterCategory = ref<string | null>(null);

const vendorGroups = ref<VendorGroup[]>([]);
const categoryGroups = ref<CategoryGroup[]>([]);

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
  { label: "OA / 办公", value: "oa" },
  { label: "网络设备", value: "network" },
  { label: "存储", value: "storage" },
  { label: "消息队列", value: "queue" },
  { label: "SCADA / 工控", value: "scada" },
  { label: "插件", value: "plugin" },
  { label: "其他", value: "other" },
];

const categoryMap: Record<string, string> = {};
categoryOptions.forEach((o) => {
  categoryMap[o.value] = o.label;
});

const sidebarMode = ref<"vendor" | "category">("vendor");

async function fetchSummary() {
  try {
    const res = await getProductSummary();
    vendorGroups.value = res.vendors || [];
    categoryGroups.value = res.categories || [];
  } catch { /* ignore */ }
}

async function fetchData() {
  loading.value = true;
  try {
    const params: Record<string, any> = {
      page: page.value,
      page_size: pageSize.value,
    };
    if (keyword.value) params.keyword = keyword.value;
    if (filterVendor.value) params.vendor = filterVendor.value;
    if (filterCategory.value) params.category = filterCategory.value;

    const res = await getProductList(params);
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
  filterVendor.value = null;
  filterCategory.value = null;
  fetchData();
}

function selectVendor(vendor: string) {
  if (filterVendor.value === vendor) {
    filterVendor.value = null;
  } else {
    filterVendor.value = vendor;
  }
  filterCategory.value = null;
  keyword.value = "";
  page.value = 1;
  fetchData();
}

function selectCategory(category: string) {
  if (filterCategory.value === category) {
    filterCategory.value = null;
  } else {
    filterCategory.value = category;
  }
  filterVendor.value = null;
  keyword.value = "";
  page.value = 1;
  fetchData();
}

function clearFilters() {
  filterVendor.value = null;
  filterCategory.value = null;
  keyword.value = "";
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
      fetchSummary();
    } catch (e: any) {
      message.error(e?.message || "创建失败");
    }
  } else if (drawerMode.value === "edit" && editingItem.value) {
    try {
      await updateProduct(editingItem.value.id, formData.value);
      message.success("更新成功");
      showDrawer.value = false;
      fetchData();
      fetchSummary();
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
    fetchSummary();
  } catch (e: any) {
    message.error(e?.message || "删除失败");
  }
}

async function handleBackfill() {
  try {
    const res = await backfillProducts();
    message.success(`回填完成：PoC ${res.poc_updated} 条，指纹 ${res.fingerprint_updated} 条`);
    fetchData();
    fetchSummary();
  } catch (e: any) {
    message.error(e?.message || "回填失败");
  }
}

async function handleReclassify() {
  try {
    const res = await reclassifyProducts();
    message.success(`重新分类完成：${res.updated} 条产品更新`);
    fetchData();
    fetchSummary();
  } catch (e: any) {
    message.error(e?.message || "重新分类失败");
  }
}

const activeFilterLabel = computed(() => {
  if (filterVendor.value) return `厂商: ${filterVendor.value}`;
  if (filterCategory.value) return `分类: ${categoryMap[filterCategory.value] || filterCategory.value}`;
  if (keyword.value) return `搜索: ${keyword.value}`;
  return null;
});

const columns = computed<DataTableColumns<Product>>(() => [
  {
    title: "产品名称",
    key: "name",
    width: 180,
    ellipsis: { tooltip: true },
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
    width: 120,
    ellipsis: { tooltip: true },
    render: (row) => row.vendor
      ? h(NButton, { text: true, size: "small", onClick: () => selectVendor(row.vendor) }, { default: () => row.vendor })
      : "-",
  },
  {
    title: "分类",
    key: "category",
    width: 100,
    render: (row) =>
      row.category
        ? h(NTag, { size: "small", bordered: false, style: { cursor: 'pointer' }, onClick: () => selectCategory(row.category) }, { default: () => categoryMap[row.category] || row.category })
        : "-",
  },
  {
    title: "PoC",
    key: "poc_count",
    width: 70,
    align: "center",
    render: (row) =>
      h(NText, { depth: row.poc_count ? 1 : 3 }, { default: () => String(row.poc_count ?? 0) }),
  },
  {
    title: "指纹",
    key: "fingerprint_count",
    width: 70,
    align: "center",
    render: (row) =>
      h(NText, { depth: row.fingerprint_count ? 1 : 3 }, { default: () => String(row.fingerprint_count ?? 0) }),
  },
  {
    title: "漏洞",
    key: "vuln_count",
    width: 70,
    align: "center",
    render: (row) =>
      h(NText, { depth: row.vuln_count ? 1 : 3 }, { default: () => String(row.vuln_count ?? 0) }),
  },
  {
    title: "操作",
    key: "actions",
    width: 120,
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

const sidebarList = computed(() => {
  if (sidebarMode.value === "vendor") {
    return vendorGroups.value.map((v) => ({
      key: v.vendor,
      label: v.vendor,
      count: v.count,
      active: filterVendor.value === v.vendor,
    }));
  }
  return categoryGroups.value.map((c) => ({
    key: c.category,
    label: categoryMap[c.category] || c.category || '未分类',
    count: c.count,
    active: filterCategory.value === c.category,
  }));
});

function onSidebarClick(key: string) {
  if (sidebarMode.value === "vendor") {
    selectVendor(key);
  } else {
    selectCategory(key);
  }
}

onMounted(() => {
  fetchData();
  fetchSummary();
});
</script>

<template>
  <div class="product-page">
    <div class="product-sidebar">
      <div class="sidebar-tabs">
        <button
          :class="['sidebar-tab', { active: sidebarMode === 'vendor' }]"
          @click="sidebarMode = 'vendor'"
        >
          按厂商
        </button>
        <button
          :class="['sidebar-tab', { active: sidebarMode === 'category' }]"
          @click="sidebarMode = 'category'"
        >
          按分类
        </button>
      </div>
      <NScrollbar style="max-height: calc(100vh - 160px)">
        <div v-if="sidebarList.length === 0" style="padding: 24px 16px; text-align: center">
          <NEmpty description="暂无数据" size="small" />
        </div>
        <div
          v-for="item in sidebarList"
          :key="item.key"
          :class="['sidebar-item', { active: item.active }]"
          @click="onSidebarClick(item.key)"
        >
          <span class="sidebar-item__label">{{ item.label }}</span>
          <span class="sidebar-item__count">{{ item.count }}</span>
        </div>
      </NScrollbar>
    </div>

    <div class="product-main">
      <NCard :bordered="false">
        <template #header>
          <div class="main-header">
            <div class="main-header__title">
              <span>产品知识库</span>
              <NTag v-if="activeFilterLabel" size="small" closable @close="clearFilters" style="margin-left: 8px">
                {{ activeFilterLabel }}
              </NTag>
            </div>
            <NSpace size="small">
              <NInputGroup>
                <NInput
                  v-model:value="keyword"
                  placeholder="搜索产品名称 / 厂商"
                  clearable
                  style="width: 200px"
                  @keydown.enter="handleSearch"
                />
                <NButton type="primary" @click="handleSearch">搜索</NButton>
              </NInputGroup>
              <NButton @click="handleReclassify">重新分类</NButton>
              <NButton @click="handleBackfill">回填关联</NButton>
              <NButton type="primary" @click="openCreate">新建产品</NButton>
            </NSpace>
          </div>
        </template>

        <NDataTable
          :columns="columns"
          :data="data"
          :loading="loading"
          remote
          :pagination="{
            page: page,
            pageSize: pageSize,
            itemCount: total,
            onUpdatePage: handlePageChange,
            showSizePicker: false,
          }"
          :row-key="(row: Product) => row.id"
          size="small"
          striped
        />
      </NCard>
    </div>

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

<style scoped>
.product-page {
  display: flex;
  gap: 0;
  height: 100%;
  min-height: 0;
}

.product-sidebar {
  width: 220px;
  min-width: 220px;
  background: var(--card-color, #fff);
  border-right: 1px solid var(--border-color, #e0e0e6);
  display: flex;
  flex-direction: column;
}

.sidebar-tabs {
  display: flex;
  border-bottom: 1px solid var(--border-color, #e0e0e6);
}

.sidebar-tab {
  flex: 1;
  padding: 10px 0;
  text-align: center;
  font-size: 13px;
  border: none;
  background: transparent;
  color: var(--text-color-2, #666);
  cursor: pointer;
  transition: all 0.2s;
}

.sidebar-tab.active {
  color: var(--primary-color, #18a058);
  font-weight: 600;
  box-shadow: inset 0 -2px 0 var(--primary-color, #18a058);
}

.sidebar-tab:hover:not(.active) {
  color: var(--text-color-1, #333);
  background: var(--hover-color, rgba(0, 0, 0, 0.04));
}

.sidebar-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 7px 14px;
  cursor: pointer;
  font-size: 13px;
  color: var(--text-color-2, #666);
  transition: all 0.15s;
  border-left: 3px solid transparent;
}

.sidebar-item:hover {
  background: var(--hover-color, rgba(0, 0, 0, 0.04));
  color: var(--text-color-1, #333);
}

.sidebar-item.active {
  background: var(--primary-color-hover, rgba(24, 160, 88, 0.08));
  color: var(--primary-color, #18a058);
  border-left-color: var(--primary-color, #18a058);
  font-weight: 500;
}

.sidebar-item__label {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sidebar-item__count {
  flex-shrink: 0;
  margin-left: 8px;
  font-size: 12px;
  color: var(--text-color-3, #999);
  background: var(--tag-color, rgba(0, 0, 0, 0.04));
  padding: 1px 6px;
  border-radius: 10px;
  min-width: 20px;
  text-align: center;
}

.sidebar-item.active .sidebar-item__count {
  color: var(--primary-color, #18a058);
  background: var(--primary-color-hover, rgba(24, 160, 88, 0.12));
}

.product-main {
  flex: 1;
  min-width: 0;
  padding: 16px;
  overflow: auto;
}

.main-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px;
}

.main-header__title {
  display: flex;
  align-items: center;
  font-size: 16px;
  font-weight: 600;
}
</style>
