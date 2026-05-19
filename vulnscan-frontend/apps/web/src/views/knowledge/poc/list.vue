<script lang="ts" setup>
import type { DataTableColumns } from "naive-ui";
import type { TestPocMatch, ValidateResult } from '#/api/poc/index';

import { computed, defineAsyncComponent, h, onMounted, ref } from "vue";

import {
  NAlert,
  NButton,
  NCard,
  NCode,
  NCollapse,
  NCollapseItem,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NDrawer,
  NDrawerContent,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPopconfirm,
  NSelect,
  NSpace,
  NSpin,
  NSwitch,
  NTabPane,
  NTabs,
  NTag,
  useMessage,
} from "naive-ui";

import {
  createPoc,
  deletePoc,
  getPocDetail,
  getPocList,
  importPocYaml,
  testPoc,
  togglePoc,
  updatePoc,
  validatePocYaml,
  type PocTemplate,
} from '#/api/poc/index';
import { sevLabels, sevColors } from '#/constants/severity';

const YamlEditor = defineAsyncComponent(() => import('./yaml-editor.vue'));

interface YamlEditorExpose {
  setMarkers: (
    markers: {
      message: string;
      startLine: number;
      endLine: number;
      severity: 'error' | 'warning';
    }[],
  ) => void;
  clearMarkers: () => void;
}

defineOptions({ name: "PocManage" });

const message = useMessage();
const loading = ref(false);
const data = ref<PocTemplate[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref("");
const severityFilter = ref<string | null>(null);

// Import
const showImport = ref(false);
const importing = ref(false);
const yamlContent = ref("");

// Editor
const showEditor = ref(false);
const editorMode = ref<"create" | "edit">("create");
const editorForm = ref({
  name: "",
  severity: "info",
  description: "",
  content: "",
  category: "",
  cve: "",
  tags: "",
});
const saving = ref(false);
const editingId = ref("");
const editorTab = ref("editor");
const yamlEditorRef = ref<YamlEditorExpose>();

// Validate
const validating = ref(false);
const validateResult = ref<ValidateResult | null>(null);

// Test
const showTestPanel = ref(false);
const testTargetUrl = ref("");
const testing = ref(false);
const testResult = ref<{
  success: boolean;
  error?: string;
  duration: string;
  findings: TestPocMatch[];
} | null>(null);

// Detail
const showDetail = ref(false);
const detailItem = ref<PocTemplate | null>(null);
const detailTab = ref("info");

const severityOptions = [
  { label: "严重", value: "critical" },
  { label: "高危", value: "high" },
  { label: "中危", value: "medium" },
  { label: "低危", value: "low" },
  { label: "信息", value: "info" },
];

const pocTemplate = `id: my-poc-template
info:
  name: 漏洞名称
  author: your-name
  severity: info
  description: 漏洞描述
  tags: tag1,tag2

http:
  - method: GET
    path:
      - "{{BaseURL}}/target-path"
    matchers:
      - type: status
        status:
          - 200
`;

const templateReferenceYaml = `id: template-id
info:
  name: 模板名称
  author: 作者
  severity: high
  description: 描述
  tags: tag1,tag2
  reference:
    - https://...

http:
  - method: GET
    path:
      - "{{BaseURL}}/path"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "keyword"
      - type: status
        status:
          - 200`;

const nucleiVariables = [
  { name: "{{BaseURL}}", desc: "完整 URL" },
  { name: "{{RootURL}}", desc: "根路径 URL" },
  { name: "{{Hostname}}", desc: "主机名" },
  { name: "{{Host}}", desc: "主机名:端口" },
  { name: "{{Port}}", desc: "端口号" },
  { name: "{{Path}}", desc: "请求路径" },
  { name: "{{Schema}}", desc: "协议 (http/https)" },
];

const matcherTypes = [
  { name: "word", desc: "关键字匹配" },
  { name: "regex", desc: "正则匹配" },
  { name: "status", desc: "HTTP 状态码" },
  { name: "binary", desc: "二进制数据匹配" },
  { name: "dsl", desc: "DSL 表达式" },
  { name: "size", desc: "响应体大小" },
];

const columns = computed<DataTableColumns<PocTemplate>>(() => [
  {
    title: "名称",
    key: "name",
    minWidth: 200,
    render: (row: PocTemplate) =>
      h(
        "a",
        {
          style: "color: #1890ff; cursor: pointer",
          onClick: () => openDetail(row),
        },
        row.name,
      ),
  },
  {
    title: "严重程度",
    key: "severity",
    width: 90,
    align: "center" as const,
    render: (row: PocTemplate) => {
      const sc = sevColors[row.severity] ?? { bg: "#f5f5f5", fg: "#999" };
      return h(
        "span",
        {
          style: `padding: 3px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; background: ${sc.bg}; color: ${sc.fg}`,
        },
        sevLabels[row.severity] ?? row.severity,
      );
    },
  },
  {
    title: "PoC ID",
    key: "poc_id",
    width: 180,
    ellipsis: { tooltip: true as const },
  },
  { title: "作者", key: "author", width: 100 },
  { title: "CVE", key: "cve", width: 130 },
  {
    title: "标签",
    key: "tags",
    width: 160,
    render: (row: PocTemplate) => {
      if (!row.tags?.length) return h("span", { style: "color: #ccc" }, "-");
      return h(NSpace, { size: 2 }, () =>
        row.tags
          .slice(0, 3)
          .map((t: string) =>
            h(NTag, { size: "tiny", bordered: false }, () => t),
          ),
      );
    },
  },
  { title: "命中", key: "hit_count", width: 60 },
  {
    title: "启用",
    key: "enabled",
    width: 70,
    render: (row: PocTemplate) =>
      h(NSwitch, {
        size: "small",
        value: row.enabled,
        onUpdateValue: (v: boolean) => handleToggle(row.id, v),
      }),
  },
  {
    title: "操作",
    key: "actions",
    width: 140,
    fixed: "right" as const,
    render: (row: PocTemplate) =>
      h(NSpace, { size: 4 }, () => [
        h(
          NButton,
          {
            size: "tiny",
            type: "info",
            secondary: true,
            onClick: () => openEdit(row),
          },
          () => "编辑",
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleDelete(row.id) },
          {
            trigger: () =>
              h(
                NButton,
                { size: "tiny", type: "error", text: true },
                () => "删除",
              ),
            default: () => "确定删除？",
          },
        ),
      ]),
  },
]);

async function fetchData() {
  loading.value = true;
  try {
    const result = await getPocList({
      page: page.value,
      page_size: pageSize.value,
      keyword: keyword.value || undefined,
      severity: severityFilter.value || undefined,
    });
    data.value = result.items ?? [];
    total.value = result.total ?? 0;
  } finally {
    loading.value = false;
  }
}

async function handleToggle(id: string, enabled: boolean) {
  try {
    await togglePoc(id, enabled);
    const item = data.value.find((d) => d.id === id);
    if (item) item.enabled = enabled;
  } catch (e: any) {
    message.error(e?.message || "操作失败");
  }
}

async function handleDelete(id: string) {
  try {
    await deletePoc(id);
    message.success("已删除");
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || "删除失败");
  }
}

async function handleImport() {
  if (!yamlContent.value.trim()) {
    message.warning("请输入 YAML 内容");
    return;
  }
  importing.value = true;
  try {
    await importPocYaml(yamlContent.value);
    message.success("导入成功");
    showImport.value = false;
    yamlContent.value = "";
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || "导入失败");
  } finally {
    importing.value = false;
  }
}

function openCreate() {
  editorMode.value = "create";
  editingId.value = "";
  editorForm.value = {
    name: "",
    severity: "info",
    description: "",
    content: pocTemplate,
    category: "",
    cve: "",
    tags: "",
  };
  editorTab.value = "editor";
  validateResult.value = null;
  testResult.value = null;
  showTestPanel.value = false;
  showEditor.value = true;
}

async function openEdit(row: PocTemplate) {
  editorMode.value = "edit";
  editingId.value = row.id;
  try {
    const detail = (await getPocDetail(row.id)) as any;
    editorForm.value = {
      name: detail.name ?? "",
      severity: detail.severity ?? "info",
      description: detail.description ?? "",
      content: detail.content ?? "",
      category: detail.category ?? "",
      cve: detail.cve ?? "",
      tags: (detail.tags ?? []).join(", "),
    };
  } catch {
    editorForm.value = {
      name: row.name,
      severity: row.severity,
      description: "",
      content: "",
      category: "",
      cve: row.cve ?? "",
      tags: (row.tags ?? []).join(", "),
    };
  }
  editorTab.value = "editor";
  validateResult.value = null;
  testResult.value = null;
  showTestPanel.value = false;
  showEditor.value = true;
}

async function handleValidate() {
  if (!editorForm.value.content.trim()) {
    message.warning("请先编写 YAML 内容");
    return;
  }
  validating.value = true;
  yamlEditorRef.value?.clearMarkers();
  try {
    const res = (await validatePocYaml(editorForm.value.content)) as any;
    validateResult.value = res;
    if (res.valid) {
      message.success("YAML 校验通过");
      if (res.name && !editorForm.value.name) editorForm.value.name = res.name;
      if (res.severity && res.severity !== "info")
        editorForm.value.severity = res.severity;
      if (res.description && !editorForm.value.description)
        editorForm.value.description = res.description;
      if (res.tags?.length && !editorForm.value.tags)
        editorForm.value.tags = res.tags.join(", ");
    } else {
      message.error(`校验失败: ${res.error}`);
      const lineMatch = res.error?.match(/line (\d+)/i);
      if (lineMatch) {
        const line = Number.parseInt(lineMatch[1]!, 10);
        yamlEditorRef.value?.setMarkers([
          {
            message: res.error!,
            startLine: line,
            endLine: line,
            severity: "error",
          },
        ]);
      }
    }
  } catch (e: any) {
    message.error(e?.message || "校验请求失败");
  } finally {
    validating.value = false;
  }
}

async function handleTest() {
  if (!editorForm.value.content.trim()) {
    message.warning("请先编写 YAML 内容");
    return;
  }
  if (!testTargetUrl.value.trim()) {
    message.warning("请输入测试目标 URL");
    return;
  }
  testing.value = true;
  testResult.value = null;
  try {
    const res = (await testPoc(
      editorForm.value.content,
      testTargetUrl.value,
    )) as any;
    testResult.value = res;
    if (res.success) {
      if (res.findings?.length) {
        message.success(
          `测试完成: 发现 ${res.findings.length} 个匹配 (${res.duration})`,
        );
      } else {
        message.info(`测试完成: 未发现匹配 (${res.duration})`);
      }
    } else {
      message.error(`测试失败: ${res.error}`);
    }
  } catch (e: any) {
    message.error(e?.message || "测试请求失败");
  } finally {
    testing.value = false;
  }
}

async function handleSave() {
  if (!editorForm.value.name || !editorForm.value.content) {
    message.warning("名称和内容不能为空");
    return;
  }
  saving.value = true;
  try {
    const payload: any = {
      name: editorForm.value.name,
      severity: editorForm.value.severity,
      description: editorForm.value.description,
      content: editorForm.value.content,
      category: editorForm.value.category,
      cve: editorForm.value.cve,
      tags: editorForm.value.tags
        .split(",")
        .map((t: string) => t.trim())
        .filter(Boolean),
    };
    if (editorMode.value === "create") {
      await createPoc(payload);
      message.success("创建成功");
    } else {
      await updatePoc(editingId.value, payload);
      message.success("更新成功");
    }
    showEditor.value = false;
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || "保存失败");
  } finally {
    saving.value = false;
  }
}

async function openDetail(row: PocTemplate) {
  try {
    detailItem.value = (await getPocDetail(row.id)) as any;
  } catch {
    detailItem.value = row;
  }
  detailTab.value = "info";
  showDetail.value = true;
}

onMounted(fetchData);
</script>

<template>
  <div style="padding: 16px">
    <NCard title="PoC 管理" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NSelect
            v-model:value="severityFilter"
            :options="severityOptions"
            placeholder="严重程度"
            size="small"
            style="width: 120px"
            clearable
            @update:value="
              () => {
                page = 1;
                fetchData();
              }
            "
          />
          <NInput
            v-model:value="keyword"
            placeholder="搜索..."
            size="small"
            clearable
            style="width: 180px"
            @keyup.enter="
              () => {
                page = 1;
                fetchData();
              }
            "
          />
          <NButton
            size="small"
            type="primary"
            @click="
              () => {
                page = 1;
                fetchData();
              }
            "
          >
            搜索
          </NButton>
          <NButton size="small" @click="showImport = true">导入 YAML</NButton>
          <NButton size="small" type="primary" @click="openCreate">
            新建
          </NButton>
        </NSpace>
      </template>

      <NDataTable
        :columns="columns"
        :data="data"
        :loading="loading"
        :bordered="false"
        size="small"
        striped
        :scroll-x="1100"
        :pagination="{
          page,
          pageSize,
          itemCount: total,
          showSizePicker: true,
          pageSizes: [20, 50, 100],
          onUpdatePage: (p: number) => {
            page = p;
            fetchData();
          },
          onUpdatePageSize: (s: number) => {
            pageSize = s;
            page = 1;
            fetchData();
          },
        }"
      />
    </NCard>

    <!-- Import Modal -->
    <NModal
      v-model:show="showImport"
      title="导入 PoC (YAML)"
      preset="card"
      style="width: 700px"
    >
      <NInput
        v-model:value="yamlContent"
        type="textarea"
        placeholder="粘贴 Nuclei 格式的 YAML..."
        :rows="18"
        style="
          font-family: &quot;SF Mono&quot;, Consolas, monospace;
          font-size: 13px;
        "
      />
      <template #footer>
        <NSpace justify="end">
          <NButton @click="showImport = false">取消</NButton>
          <NButton type="primary" :loading="importing" @click="handleImport">
            导入
          </NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- Editor Modal (Full-featured) -->
    <NModal
      v-model:show="showEditor"
      :title="editorMode === 'create' ? '新建 PoC' : '编辑 PoC'"
      preset="card"
      style="width: 1100px; max-width: 95vw"
    >
      <div style="display: flex; gap: 16px; min-height: 600px">
        <!-- Left: YAML Editor -->
        <div
          style="flex: 1; min-width: 0; display: flex; flex-direction: column"
        >
          <div
            style="
              display: flex;
              align-items: center;
              justify-content: space-between;
              margin-bottom: 8px;
            "
          >
            <NSpace :size="8" align="center">
              <span style="font-weight: 600; font-size: 14px">YAML 编辑器</span>
              <NTag
                v-if="validateResult?.valid"
                size="small"
                type="success"
                :bordered="false"
              >
                校验通过
              </NTag>
              <NTag
                v-else-if="validateResult && !validateResult.valid"
                size="small"
                type="error"
                :bordered="false"
              >
                校验失败
              </NTag>
            </NSpace>
            <NSpace :size="6">
              <NButton
                size="small"
                :loading="validating"
                @click="handleValidate"
              >
                校验 YAML
              </NButton>
              <NButton
                size="small"
                type="warning"
                @click="showTestPanel = !showTestPanel"
              >
                {{ showTestPanel ? "关闭测试" : "测试 PoC" }}
              </NButton>
            </NSpace>
          </div>

          <div style="flex: 1; min-height: 0">
            <YamlEditor
              ref="yamlEditorRef"
              v-model:model-value="editorForm.content"
              :height="showTestPanel ? '360px' : '520px'"
            />
          </div>

          <!-- Test Panel -->
          <div v-if="showTestPanel" style="margin-top: 12px">
            <NCard size="small" title="PoC 测试">
              <NSpace align="center" :size="8">
                <NInput
                  v-model:value="testTargetUrl"
                  placeholder="输入目标 URL, 如 https://example.com"
                  size="small"
                  style="width: 380px"
                  @keyup.enter="handleTest"
                />
                <NButton
                  size="small"
                  type="primary"
                  :loading="testing"
                  :disabled="
                    !testTargetUrl.trim() || !editorForm.content.trim()
                  "
                  @click="handleTest"
                >
                  执行测试
                </NButton>
              </NSpace>

              <div v-if="testing" style="margin-top: 12px; text-align: center">
                <NSpin size="small" />
                <span style="margin-left: 8px; color: #999; font-size: 12px">
                  正在执行 PoC 测试...
                </span>
              </div>

              <div v-if="testResult && !testing" style="margin-top: 12px">
                <NAlert
                  v-if="!testResult.success"
                  type="error"
                  :title="testResult.error"
                  style="margin-bottom: 8px"
                />
                <template v-else>
                  <NAlert
                    v-if="testResult.findings?.length"
                    type="success"
                    style="margin-bottom: 8px"
                  >
                    发现 {{ testResult.findings.length }} 个匹配，耗时
                    {{ testResult.duration }}
                  </NAlert>
                  <NAlert v-else type="info" style="margin-bottom: 8px">
                    未发现匹配，耗时 {{ testResult.duration }}
                  </NAlert>

                  <NCollapse v-if="testResult.findings?.length">
                    <NCollapseItem
                      v-for="(f, i) in testResult.findings"
                      :key="i"
                      :name="i"
                    >
                      <template #header>
                        <NSpace align="center" :size="6">
                          <span
                            :style="{
                              padding: '2px 8px',
                              borderRadius: '3px',
                              fontSize: '11px',
                              fontWeight: 600,
                              background: (
                                sevColors[f.severity] ?? { bg: '#f5f5f5' }
                              ).bg,
                              color: (sevColors[f.severity] ?? { fg: '#999' })
                                .fg,
                            }"
                          >
                            {{ sevLabels[f.severity] ?? f.severity }}
                          </span>
                          <span style="font-size: 13px">{{ f.name }}</span>
                          <NTag
                            v-if="f.matcher_name"
                            size="tiny"
                            :bordered="false"
                          >
                            {{ f.matcher_name }}
                          </NTag>
                        </NSpace>
                      </template>
                      <div style="font-size: 12px">
                        <p><b>匹配位置:</b> {{ f.matched_at }}</p>
                        <pre
                          v-if="f.evidence"
                          style="
                            padding: 10px;
                            background: #1e1e2e;
                            color: #cdd6f4;
                            border-radius: 6px;
                            font-size: 11px;
                            overflow-x: auto;
                            white-space: pre-wrap;
                            word-break: break-all;
                            max-height: 300px;
                            line-height: 1.5;
                            margin: 8px 0;
                            font-family:
                              &quot;SF Mono&quot;, Consolas, monospace;
                          "
                          >{{ f.evidence }}</pre
                        >
                        <NCode
                          v-if="f.curl_command"
                          :code="f.curl_command"
                          language="bash"
                          style="margin-top: 6px"
                        />
                      </div>
                    </NCollapseItem>
                  </NCollapse>
                </template>
              </div>
            </NCard>
          </div>
        </div>

        <!-- Right: Metadata Panel -->
        <div style="width: 320px; flex-shrink: 0">
          <NTabs v-model:value="editorTab" size="small" type="line">
            <NTabPane name="editor" tab="基本信息">
              <NForm label-placement="top" size="small" style="margin-top: 4px">
                <NFormItem label="名称">
                  <NInput
                    v-model:value="editorForm.name"
                    placeholder="PoC 名称"
                  />
                </NFormItem>
                <NFormItem label="严重程度">
                  <NSelect
                    v-model:value="editorForm.severity"
                    :options="severityOptions"
                  />
                </NFormItem>
                <NFormItem label="CVE">
                  <NInput
                    v-model:value="editorForm.cve"
                    placeholder="CVE-YYYY-XXXXX"
                  />
                </NFormItem>
                <NFormItem label="分类">
                  <NInput
                    v-model:value="editorForm.category"
                    placeholder="如 cnvd, cve, misc"
                  />
                </NFormItem>
                <NFormItem label="标签">
                  <NInput
                    v-model:value="editorForm.tags"
                    placeholder="逗号分隔: rce, sqli"
                  />
                </NFormItem>
                <NFormItem label="描述">
                  <NInput
                    v-model:value="editorForm.description"
                    type="textarea"
                    :rows="3"
                    placeholder="漏洞描述"
                  />
                </NFormItem>
              </NForm>

              <!-- Validate result detail -->
              <div
                v-if="validateResult?.valid"
                style="
                  padding: 10px;
                  background: #f6ffed;
                  border-radius: 6px;
                  border: 1px solid #b7eb8f;
                  font-size: 12px;
                  margin-top: 4px;
                "
              >
                <p style="margin: 0 0 4px; font-weight: 600; color: #389e0d">
                  解析结果
                </p>
                <p style="margin: 2px 0; color: #555">
                  ID: {{ validateResult.id }}
                </p>
                <p style="margin: 2px 0; color: #555">
                  Name: {{ validateResult.name }}
                </p>
                <p
                  v-if="validateResult.author"
                  style="margin: 2px 0; color: #555"
                >
                  Author: {{ validateResult.author }}
                </p>
                <p
                  v-if="validateResult.severity"
                  style="margin: 2px 0; color: #555"
                >
                  Severity: {{ validateResult.severity }}
                </p>
                <p
                  v-if="validateResult.tags?.length"
                  style="margin: 2px 0; color: #555"
                >
                  Tags: {{ validateResult.tags?.join(", ") }}
                </p>
              </div>
            </NTabPane>

            <NTabPane name="help" tab="模板参考">
              <div style="font-size: 12px; color: #666; line-height: 1.8">
                <p style="font-weight: 600; margin-bottom: 4px">
                  Nuclei YAML 模板结构
                </p>
                <pre
                  style="
                    padding: 10px;
                    background: #f5f5f5;
                    border-radius: 6px;
                    font-size: 11px;
                    line-height: 1.6;
                    white-space: pre-wrap;
                    font-family: &quot;SF Mono&quot;, Consolas, monospace;
                  "
                  >{{ templateReferenceYaml }}</pre
                >

                <p style="font-weight: 600; margin: 12px 0 4px">常用变量</p>
                <ul
                  style="
                    padding-left: 16px;
                    margin: 0;
                    list-style: disc;
                    font-size: 12px;
                  "
                >
                  <li v-for="item in nucleiVariables" :key="item.name">
                    <code style="color: #d63384">{{ item.name }}</code>
                    {{ item.desc }}
                  </li>
                </ul>

                <p style="font-weight: 600; margin: 12px 0 4px">匹配器类型</p>
                <ul
                  style="
                    padding-left: 16px;
                    margin: 0;
                    list-style: disc;
                    font-size: 12px;
                  "
                >
                  <li v-for="item in matcherTypes" :key="item.name">
                    <b>{{ item.name }}</b> - {{ item.desc }}
                  </li>
                </ul>
              </div>
            </NTabPane>
          </NTabs>
        </div>
      </div>

      <template #footer>
        <NSpace justify="end">
          <NButton @click="showEditor = false">取消</NButton>
          <NButton type="primary" :loading="saving" @click="handleSave">
            {{ editorMode === "create" ? "创建" : "保存" }}
          </NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- Detail Drawer -->
    <NDrawer v-model:show="showDetail" :width="650">
      <NDrawerContent v-if="detailItem" :title="detailItem.name">
        <template #header>
          <div
            style="
              display: flex;
              gap: 12px;
              align-items: center;
              justify-content: space-between;
              width: 100%;
            "
          >
            <span style="font-weight: 600">{{ detailItem.name }}</span>
            <NSpace :size="8">
              <span
                :style="{
                  padding: '3px 10px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  fontWeight: 600,
                  background: (
                    sevColors[detailItem.severity] ?? { bg: '#f5f5f5' }
                  ).bg,
                  color: (sevColors[detailItem.severity] ?? { fg: '#999' }).fg,
                }"
              >
                {{ sevLabels[detailItem.severity] ?? detailItem.severity }}
              </span>
              <NTag
                v-if="detailItem.enabled"
                size="small"
                type="success"
                :bordered="false"
              >
                启用
              </NTag>
              <NTag v-else size="small" :bordered="false">停用</NTag>
            </NSpace>
          </div>
        </template>

        <NTabs v-model:value="detailTab" size="small" type="line">
          <NTabPane name="info" tab="基本信息">
            <NDescriptions
              label-placement="left"
              bordered
              :column="2"
              size="small"
              style="margin-top: 8px"
            >
              <NDescriptionsItem label="PoC ID">
                {{ detailItem.poc_id }}
              </NDescriptionsItem>
              <NDescriptionsItem label="作者">
                {{ detailItem.author || "-" }}
              </NDescriptionsItem>
              <NDescriptionsItem label="CVE">
                {{ detailItem.cve || "-" }}
              </NDescriptionsItem>
              <NDescriptionsItem label="CWE">
                {{ (detailItem as any).cwe || "-" }}
              </NDescriptionsItem>
              <NDescriptionsItem label="CVSS">
                {{ (detailItem as any).cvss || "-" }}
              </NDescriptionsItem>
              <NDescriptionsItem label="命中数">
                {{ detailItem.hit_count }}
              </NDescriptionsItem>
              <NDescriptionsItem label="来源">
                {{ detailItem.source || "-" }}
              </NDescriptionsItem>
              <NDescriptionsItem label="分类">
                {{ (detailItem as any).category || "-" }}
              </NDescriptionsItem>
              <NDescriptionsItem :span="2" label="标签">
                <NSpace v-if="detailItem.tags?.length" :size="4">
                  <NTag
                    v-for="t in detailItem.tags"
                    :key="t"
                    size="tiny"
                    :bordered="false"
                  >
                    {{ t }}
                  </NTag>
                </NSpace>
                <span v-else style="color: #ccc">-</span>
              </NDescriptionsItem>
              <NDescriptionsItem :span="2" label="描述">
                {{ detailItem.description || "-" }}
              </NDescriptionsItem>
            </NDescriptions>
          </NTabPane>
          <NTabPane name="yaml" tab="YAML 内容">
            <YamlEditor
              :model-value="(detailItem as any).content || ''"
              :readonly="true"
              height="500px"
            />
          </NTabPane>
        </NTabs>
      </NDrawerContent>
    </NDrawer>
  </div>
</template>
