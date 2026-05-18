<script lang="ts" setup>
import { computed, h, nextTick, onMounted, ref } from 'vue';
import {
  NButton,
  NCard,
  NDataTable,
  NEmpty,
  NForm,
  NFormItem,
  NGrid,
  NGridItem,
  NInput,
  NInputNumber,
  NModal,
  NProgress,
  NSpace,
  NStatistic,
  NTag,
  useMessage,
} from 'naive-ui';

import type { ComplianceReport, FrameworkSummary, Rule } from '#/api/compliance';
import { getFrameworks, getRules, runCheck } from '#/api/compliance';

defineOptions({ name: 'ComplianceIndex' });

const message = useMessage();

const frameworks = ref<FrameworkSummary[]>([]);
const frameworksLoading = ref(false);
const rulesLoading = ref(false);
const selectedFw = ref<FrameworkSummary | null>(null);
const rulesByFramework = ref<Record<string, Rule[]>>({});
const reportsByFramework = ref<Record<string, ComplianceReport>>({});

const showCheckModal = ref(false);
const checking = ref(false);
const resultSectionRef = ref<HTMLElement | null>(null);
const activeCheckFramework = ref<FrameworkSummary | null>(null);

const checkForm = ref({
  framework_id: '',
  target_ip: '',
  username: 'root',
  password: '',
  port: 22,
});

const currentRules = computed(() => {
  if (!selectedFw.value) return [];
  return rulesByFramework.value[selectedFw.value.id] ?? [];
});

const currentReport = computed(() => {
  if (!selectedFw.value) return null;
  return reportsByFramework.value[selectedFw.value.id] ?? null;
});

const fwColumns = [
  { title: '名称', key: 'name', minWidth: 220 },
  { title: '标准', key: 'standard', width: 90 },
  { title: '版本', key: 'version', width: 90 },
  { title: '规则数', key: 'rule_count', width: 90 },
  { title: '描述', key: 'description', ellipsis: { tooltip: true } },
  {
    title: '操作',
    key: 'actions',
    width: 190,
    render: (row: FrameworkSummary) =>
      h(NSpace, { size: 6 }, () => [
        h(
          NButton,
          { size: 'small', type: selectedFw.value?.id === row.id ? 'primary' : 'default', onClick: () => selectFw(row) },
          () => '查看规则',
        ),
        h(NButton, { size: 'small', type: 'info', onClick: () => openCheck(row) }, () => '执行检查'),
      ]),
  },
];

const ruleColumns = [
  { title: '规则ID', key: 'id', width: 120 },
  { title: '分类', key: 'category', width: 110 },
  { title: '规则标题', key: 'title', minWidth: 240 },
  {
    title: '风险',
    key: 'severity',
    width: 90,
    render: (row: Rule) => {
      const typeMap: Record<string, 'default' | 'error' | 'warning' | 'info'> = {
        high: 'error',
        medium: 'warning',
        low: 'info',
      };
      return h(NTag, { size: 'small', type: typeMap[row.severity] ?? 'default', bordered: false }, () => row.severity);
    },
  },
  { title: '修复建议', key: 'remediation', ellipsis: { tooltip: true } },
];

const resultColumns = [
  { title: '规则ID', key: 'rule_id', width: 120 },
  {
    title: '状态',
    key: 'status',
    width: 90,
    render: (row: Record<string, any>) => {
      const typeMap: Record<string, 'default' | 'success' | 'error' | 'warning'> = {
        pass: 'success',
        fail: 'error',
        skip: 'default',
        error: 'warning',
      };
      return h(NTag, { size: 'small', type: typeMap[row.status] ?? 'default', bordered: false }, () => row.status);
    },
  },
  { title: '期望值', key: 'expected', width: 160, ellipsis: { tooltip: true } },
  { title: '实际值', key: 'actual', width: 160, ellipsis: { tooltip: true } },
  { title: '证据', key: 'evidence', ellipsis: { tooltip: true } },
];

async function fetchFrameworks() {
  frameworksLoading.value = true;
  try {
    const res: any = await getFrameworks();
    frameworks.value = (res?.data ?? res) ?? [];
    if (!selectedFw.value && frameworks.value.length > 0) {
      await selectFw(frameworks.value[0]);
    }
  } catch {
    message.error('加载基线框架失败');
  } finally {
    frameworksLoading.value = false;
  }
}

async function loadRules(fw: FrameworkSummary, force = false) {
  if (!force && rulesByFramework.value[fw.id]) {
    return;
  }
  rulesLoading.value = true;
  try {
    const res: any = await getRules(fw.id);
    rulesByFramework.value[fw.id] = (res?.data ?? res) ?? [];
  } catch {
    rulesByFramework.value[fw.id] = [];
    message.error('加载规则详情失败');
  } finally {
    rulesLoading.value = false;
  }
}

async function selectFw(fw: FrameworkSummary) {
  selectedFw.value = fw;
  await loadRules(fw);
}

function openCheck(fw: FrameworkSummary) {
  activeCheckFramework.value = fw;
  checkForm.value.framework_id = fw.id;
  showCheckModal.value = true;
}

async function onRunCheck() {
  if (!checkForm.value.target_ip) {
    message.warning('请填写目标主机 IP');
    return;
  }
  checking.value = true;
  try {
    const res: any = await runCheck(checkForm.value);
    const body = res?.data ?? res;
    const report = body?.report ?? null;
    if (!report) {
      message.warning('本次检查未返回结果');
      return;
    }
    reportsByFramework.value[report.framework_id] = report;
    const fw = frameworks.value.find((item) => item.id === report.framework_id) ?? activeCheckFramework.value;
    if (fw) {
      await selectFw(fw);
    }
    showCheckModal.value = false;
    message.success(`检查完成，得分 ${report.score.toFixed(1)}%`);
    await nextTick();
    resultSectionRef.value?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch {
    message.error('执行基线检查失败');
  } finally {
    checking.value = false;
  }
}

const frameworkRowProps = (row: FrameworkSummary) => ({
  style: 'cursor: pointer;',
  onClick: () => selectFw(row),
});

onMounted(fetchFrameworks);
</script>

<template>
  <div class="baseline-page">
    <div class="baseline-layout">
      <NCard class="baseline-sidebar" title="基线框架" size="small">
        <template #header-extra>
          <NTag size="small" :bordered="false">{{ frameworks.length }} 套</NTag>
        </template>
        <NDataTable
          :columns="fwColumns"
          :data="frameworks"
          :loading="frameworksLoading"
          :bordered="false"
          :pagination="false"
          :max-height="680"
          size="small"
          :row-props="frameworkRowProps"
        />
      </NCard>

      <div class="baseline-main">
        <NCard v-if="selectedFw" size="small" class="baseline-overview" :title="selectedFw.name">
          <template #header-extra>
            <NSpace :size="8">
              <NButton size="small" @click="loadRules(selectedFw, true)">刷新规则</NButton>
              <NButton size="small" type="primary" @click="openCheck(selectedFw)">执行检查</NButton>
            </NSpace>
          </template>
          <NGrid :cols="4" :x-gap="12" :y-gap="12">
            <NGridItem>
              <NStatistic label="规则数" :value="currentRules.length || selectedFw.rule_count" />
            </NGridItem>
            <NGridItem>
              <NStatistic label="标准" :value="selectedFw.standard || '-'" />
            </NGridItem>
            <NGridItem>
              <NStatistic label="版本" :value="selectedFw.version || '-'" />
            </NGridItem>
            <NGridItem>
              <NStatistic
                label="最近得分"
                :value="currentReport ? `${currentReport.score.toFixed(1)}%` : '未检查'"
              />
            </NGridItem>
          </NGrid>
          <div class="baseline-description">
            {{ selectedFw.description || '暂无描述' }}
          </div>
        </NCard>

        <NEmpty v-else description="请选择一套基线框架" class="baseline-empty" />

        <NCard title="规则详情" size="small" class="baseline-section">
          <NEmpty v-if="!selectedFw" description="请选择一套基线框架后查看规则" />
          <NDataTable
            v-else
            :columns="ruleColumns"
            :data="currentRules"
            :loading="rulesLoading"
            :bordered="false"
            size="small"
            striped
            :max-height="340"
          />
        </NCard>

        <div ref="resultSectionRef">
          <NCard title="检查结果" size="small" class="baseline-section">
          <NEmpty v-if="!selectedFw" description="请选择一套基线框架后查看结果" />
          <NEmpty v-else-if="!currentReport" description="当前基线暂未执行检查" />
          <template v-else>
            <NGrid :cols="4" :x-gap="12" style="margin-bottom: 16px">
              <NGridItem>
                <NCard size="small">
                  <NStatistic label="总规则数" :value="currentReport.total_rules" />
                </NCard>
              </NGridItem>
              <NGridItem>
                <NCard size="small">
                  <NStatistic label="通过" :value="currentReport.passed_rules" />
                </NCard>
              </NGridItem>
              <NGridItem>
                <NCard size="small">
                  <NStatistic label="失败" :value="currentReport.failed_rules" />
                </NCard>
              </NGridItem>
              <NGridItem>
                <NCard size="small">
                  <div class="baseline-score">
                    <div class="baseline-score__label">得分</div>
                    <NProgress
                      type="circle"
                      :percentage="Math.round(currentReport.score)"
                      :stroke-width="7"
                      style="width: 72px"
                    />
                  </div>
                </NCard>
              </NGridItem>
            </NGrid>

            <NDataTable
              :columns="resultColumns"
              :data="currentReport.results"
              :bordered="false"
              size="small"
              striped
              :max-height="360"
            />
          </template>
          </NCard>
        </div>
      </div>
    </div>

    <NModal v-model:show="showCheckModal" preset="card" :title="`执行基线检查${activeCheckFramework ? ` - ${activeCheckFramework.name}` : ''}`" style="width: 480px">
      <NForm label-placement="left" label-width="90">
        <NFormItem label="目标主机 IP" required>
          <NInput v-model:value="checkForm.target_ip" placeholder="请输入目标主机 IP" />
        </NFormItem>
        <NFormItem label="登录账号">
          <NInput v-model:value="checkForm.username" />
        </NFormItem>
        <NFormItem label="登录密码">
          <NInput v-model:value="checkForm.password" type="password" show-password-on="click" />
        </NFormItem>
        <NFormItem label="SSH 端口">
          <NInputNumber v-model:value="checkForm.port" :min="1" :max="65535" />
        </NFormItem>
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

<style scoped>
.baseline-page {
  padding: 16px;
}

.baseline-layout {
  display: grid;
  grid-template-columns: minmax(420px, 34%) minmax(0, 1fr);
  gap: 16px;
  align-items: start;
}

.baseline-sidebar,
.baseline-main,
.baseline-section,
.baseline-overview {
  min-width: 0;
}

.baseline-main {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.baseline-description {
  margin-top: 12px;
  color: var(--n-text-color-3);
  line-height: 1.6;
}

.baseline-score {
  display: flex;
  min-height: 108px;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 8px;
}

.baseline-score__label {
  color: var(--n-text-color-3);
  font-size: 12px;
}

.baseline-empty {
  padding: 32px 0;
}

@media (max-width: 1280px) {
  .baseline-layout {
    grid-template-columns: 1fr;
  }
}
</style>
