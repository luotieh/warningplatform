<script lang="ts" setup>
import { h, onMounted, ref } from 'vue';
import {
  NButton, NCard, NDataTable, NEmpty, NForm, NFormItem, NGrid, NGridItem,
  NInput, NInputNumber, NModal, NProgress, NSelect, NSpace, NStatistic,
  NTabPane, NTabs, NTag, useMessage,
} from 'naive-ui';
import type { ComplianceReport, FrameworkSummary, Rule } from '#/api/compliance';
import { getFrameworks, getRules, runCheck } from '#/api/compliance';

defineOptions({ name: 'ComplianceIndex' });

const message = useMessage();
const frameworks = ref<FrameworkSummary[]>([]);
const loading = ref(false);
const selectedFw = ref<FrameworkSummary | null>(null);
const rules = ref<Rule[]>([]);

const showCheckModal = ref(false);
const checkForm = ref({ framework_id: '', target_ip: '', username: 'root', password: '', port: 22 });
const checking = ref(false);
const report = ref<ComplianceReport | null>(null);

const fwColumns = [
  { title: '名称', key: 'name', minWidth: 200 },
  { title: '标准', key: 'standard', width: 80 },
  { title: '版本', key: 'version', width: 80 },
  { title: '规则数', key: 'rule_count', width: 80 },
  { title: '描述', key: 'description', ellipsis: { tooltip: true } },
  {
    title: '操作', key: 'actions', width: 200,
    render: (row: FrameworkSummary) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'small', type: 'info', onClick: () => selectFw(row) }, () => '查看规则'),
      h(NButton, { size: 'small', type: 'primary', onClick: () => openCheck(row) }, () => '执行检查'),
    ]),
  },
];

const ruleColumns = [
  { title: 'ID', key: 'id', width: 110 },
  { title: '分类', key: 'category', width: 100 },
  { title: '检查项', key: 'title', minWidth: 200 },
  {
    title: '级别', key: 'severity', width: 70,
    render: (row: Rule) => {
      const typeMap: Record<string, any> = { high: 'error', medium: 'warning', low: 'info' };
      return h(NTag, { size: 'small', type: typeMap[row.severity] ?? 'default' }, () => row.severity);
    },
  },
  { title: '修复建议', key: 'remediation', ellipsis: { tooltip: true } },
];

const resultColumns = [
  { title: '规则ID', key: 'rule_id', width: 110 },
  {
    title: '状态', key: 'status', width: 80,
    render: (row: any) => {
      const typeMap: Record<string, any> = { pass: 'success', fail: 'error', skip: 'default', error: 'warning' };
      return h(NTag, { size: 'small', type: typeMap[row.status] ?? 'default' }, () => row.status);
    },
  },
  { title: '期望值', key: 'expected', width: 140, ellipsis: { tooltip: true } },
  { title: '实际值', key: 'actual', width: 140, ellipsis: { tooltip: true } },
  { title: '证据', key: 'evidence', ellipsis: { tooltip: true } },
];

async function fetchFrameworks() {
  loading.value = true;
  try {
    const res: any = await getFrameworks();
    frameworks.value = (res?.data ?? res) ?? [];
  } catch { message.error('获取基线列表失败'); }
  finally { loading.value = false; }
}

async function selectFw(fw: FrameworkSummary) {
  selectedFw.value = fw;
  try {
    const res: any = await getRules(fw.id);
    rules.value = (res?.data ?? res) ?? [];
  } catch { rules.value = []; }
}

function openCheck(fw: FrameworkSummary) {
  checkForm.value.framework_id = fw.id;
  report.value = null;
  showCheckModal.value = true;
}

async function onRunCheck() {
  if (!checkForm.value.target_ip) { message.warning('请输入目标IP'); return; }
  checking.value = true;
  try {
    const res: any = await runCheck(checkForm.value);
    const body = res?.data ?? res;
    report.value = body?.report ?? null;
    if (report.value) {
      message.success(`检查完成: 得分 ${report.value.score.toFixed(1)}%`);
    }
  } catch { message.error('检查执行失败'); }
  finally { checking.value = false; }
}

onMounted(fetchFrameworks);
</script>

<template>
  <div style="padding: 16px">
    <NTabs type="line" size="small">
      <NTabPane name="frameworks" tab="基线管理">
        <NDataTable :columns="fwColumns" :data="frameworks" :loading="loading" :bordered="false" size="small" />
      </NTabPane>

      <NTabPane name="rules" :tab="`规则详情${selectedFw ? ` - ${selectedFw.name}` : ''}`">
        <NEmpty v-if="!selectedFw" description="请先在「基线管理」中选择一个框架查看规则" />
        <template v-else>
          <NCard :title="selectedFw.name" size="small" style="margin-bottom:12px">
            <NGrid :cols="3" :x-gap="12">
              <NGridItem><NStatistic label="规则数" :value="rules.length" /></NGridItem>
              <NGridItem><NStatistic label="标准" :value="selectedFw.standard" /></NGridItem>
              <NGridItem><NStatistic label="版本" :value="selectedFw.version" /></NGridItem>
            </NGrid>
          </NCard>
          <NDataTable :columns="ruleColumns" :data="rules" :bordered="false" size="small" striped :max-height="400" />
        </template>
      </NTabPane>

      <NTabPane name="results" tab="检查结果">
        <NEmpty v-if="!report" description="请选择基线并执行检查" />
        <template v-else>
          <NGrid :cols="4" :x-gap="12" style="margin-bottom:16px">
            <NGridItem><NCard size="small"><NStatistic label="总规则" :value="report.total_rules" /></NCard></NGridItem>
            <NGridItem><NCard size="small"><NStatistic label="通过" :value="report.passed_rules" /></NCard></NGridItem>
            <NGridItem><NCard size="small"><NStatistic label="失败" :value="report.failed_rules" /></NCard></NGridItem>
            <NGridItem>
              <NCard size="small">
                <div style="text-align:center">
                  <div style="font-size:12px;color:#666;margin-bottom:4px">得分</div>
                  <NProgress type="circle" :percentage="Math.round(report.score)" :stroke-width="6" style="width:60px" />
                </div>
              </NCard>
            </NGridItem>
          </NGrid>
          <NDataTable :columns="resultColumns" :data="report.results" :bordered="false" size="small" striped :max-height="400" />
        </template>
      </NTabPane>
    </NTabs>

    <!-- 执行检查弹窗 -->
    <NModal v-model:show="showCheckModal" preset="card" title="执行合规检查" style="width:480px">
      <NForm label-placement="left" label-width="80">
        <NFormItem label="目标IP" required><NInput v-model:value="checkForm.target_ip" placeholder="目标主机IP" /></NFormItem>
        <NFormItem label="用户名"><NInput v-model:value="checkForm.username" /></NFormItem>
        <NFormItem label="密码"><NInput v-model:value="checkForm.password" type="password" show-password-on="click" /></NFormItem>
        <NFormItem label="端口"><NInputNumber v-model:value="checkForm.port" :min="1" :max="65535" /></NFormItem>
      </NForm>
      <template #action>
        <NSpace justify="end">
          <NButton @click="showCheckModal = false">取消</NButton>
          <NButton type="primary" :loading="checking" @click="onRunCheck">开始检查</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>
