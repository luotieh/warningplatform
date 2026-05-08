<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import { computed, h } from 'vue';

import {
  NCard,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NTag,
} from 'naive-ui';

const props = defineProps<{ result: any }>();

const r = computed(() => props.result || {});
const dns = computed(() => r.value.dns || {});
const httpInfo = computed(() => r.value.http || {});
const ssl = computed(() => r.value.ssl || {});
const timing = computed(() => r.value.timing || {});

const multiDnsRows = computed(() =>
  Object.entries(dns.value.multi_dns || {}).map(([name, ips]) => ({
    ips: Array.isArray(ips) ? (ips as string[]).join(', ') : String(ips),
    name,
  })),
);

const respHeaderRows = computed(() =>
  Object.entries(httpInfo.value.response_headers || {}).map(([k, v]) => ({
    key: k,
    value: v as string,
  })),
);

const errors = computed<string[]>(() => r.value.errors || []);
const warnings = computed<string[]>(() => r.value.warnings || []);

type TagType = 'default' | 'error' | 'info' | 'primary' | 'success' | 'warning';

function sevTag(s: string): TagType {
  const m: Record<string, TagType> = {
    acceptable: 'warning',
    critical: 'error',
    high: 'error',
    low: 'info',
    medium: 'warning',
    strong: 'success',
    weak: 'error',
  };
  return m[s] || 'info';
}

function sevLabel(s: string) {
  const m: Record<string, string> = {
    acceptable: '可接受',
    critical: '严重',
    high: '高危',
    low: '低危',
    medium: '中危',
    normal: '正常',
    strong: '强',
    weak: '弱',
  };
  return m[s] || s || '-';
}

const multiDnsCols: DataTableColumns<{ name: string; ips: string }> = [
  { key: 'name', title: 'DNS服务器', minWidth: 160 },
  {
    key: 'ips',
    title: '解析结果',
    minWidth: 200,
    ellipsis: { tooltip: true },
  },
];

const redirectCols: DataTableColumns<any> = [
  { key: 'index', title: '#', width: 44, render: (_, i) => i + 1 },
  {
    key: 'url',
    title: '来源URL',
    minWidth: 200,
    ellipsis: { tooltip: true },
  },
  {
    key: 'status_code',
    title: '状态码',
    width: 80,
    render: (row) =>
      h('span', { class: 'font-mono' }, String(row.status_code ?? '-')),
  },
  {
    key: 'location',
    title: '跳转到',
    minWidth: 200,
    ellipsis: { tooltip: true },
  },
  {
    key: 'time_ms',
    title: '耗时(ms)',
    width: 88,
    render: (row) => h('span', { class: 'font-mono' }, String(row.time_ms ?? '-')),
  },
];

const headerCols: DataTableColumns<{ key: string; value: string }> = [
  { key: 'key', title: 'Header名', minWidth: 200 },
  {
    key: 'value',
    title: '值',
    minWidth: 240,
    ellipsis: { tooltip: true },
    render: (row) =>
      h('span', { class: 'font-mono text-xs' }, row.value ?? '-'),
  },
];

const securityIssueCols: DataTableColumns<any> = [
  {
    key: 'type',
    title: '类型',
    minWidth: 160,
    ellipsis: { tooltip: true },
  },
  {
    key: 'name',
    title: '规则名',
    minWidth: 160,
    ellipsis: { tooltip: true },
  },
  {
    key: 'severity',
    title: '严重程度',
    width: 96,
    render: (row) =>
      h(
        NTag,
        {
          type: sevTag(row.severity || 'low'),
          size: 'small',
          bordered: false,
        },
        { default: () => sevLabel(row.severity) },
      ),
  },
  {
    key: 'detail',
    title: '详情',
    minWidth: 240,
    ellipsis: { tooltip: true },
  },
];
</script>

<template>
  <div class="space-y-3">
    <NCard size="small" title="综合状态">
      <NDescriptions :column="4" bordered size="small">
        <NDescriptionsItem label="可用性">
          <NTag :type="r.available ? 'success' : 'error'" size="small" :bordered="false">
            {{ r.available ? '可用' : '不可用' }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="HTTP状态码">
          <span
            class="font-mono font-bold"
            :class="
              r.status_code != null && r.status_code >= 200 && r.status_code < 400
                ? 'text-green-500'
                : 'text-red-500'
            "
          >
            {{ r.status_code ?? '-' }}
          </span>
        </NDescriptionsItem>
        <NDescriptionsItem label="响应总耗时">
          <span class="font-mono">{{ timing.total_ms ?? '-' }} ms</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="目标URL" :span="3">
          <span class="font-mono break-all text-xs">{{ r.url || '-' }}</span>
        </NDescriptionsItem>
      </NDescriptions>
    </NCard>

    <NCard size="small" title="分段耗时">
      <NDescriptions :column="5" bordered size="small">
        <NDescriptionsItem label="DNS解析">
          <span class="font-mono">{{ timing.dns_ms ?? '-' }} ms</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="TCP连接">
          <span class="font-mono">{{ timing.tcp_connect_ms ?? '-' }} ms</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="TLS握手">
          <span class="font-mono">{{ timing.tls_handshake_ms ?? '-' }} ms</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="首字节TTFB">
          <span class="font-mono">{{ timing.ttfb_ms ?? '-' }} ms</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="合计">
          <span class="font-mono font-bold">{{ timing.total_ms ?? '-' }} ms</span>
        </NDescriptionsItem>
      </NDescriptions>
    </NCard>

    <NCard size="small" title="DNS 解析">
      <NDescriptions :column="3" bordered size="small" class="mb-3">
        <NDescriptionsItem label="解析IP">
          <span class="font-mono text-xs">
            {{ (dns.resolved_ips || []).join(', ') || '-' }}
          </span>
        </NDescriptionsItem>
        <NDescriptionsItem label="多DNS一致性">
          <NTag
            :type="dns.dns_consistent === false ? 'error' : 'success'"
            size="small"
            :bordered="false"
          >
            {{ dns.dns_consistent === false ? '不一致' : '一致' }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="预期IP匹配">
          <NTag
            v-if="dns.expected_ip_match != null"
            :type="dns.expected_ip_match ? 'success' : 'error'"
            size="small"
            :bordered="false"
          >
            {{ dns.expected_ip_match ? '匹配' : '不匹配' }}
          </NTag>
          <span v-else class="text-muted-foreground text-xs">未配置</span>
        </NDescriptionsItem>
      </NDescriptions>
      <NDataTable
        v-if="multiDnsRows.length"
        :columns="multiDnsCols"
        :data="multiDnsRows"
        size="small"
        :max-height="200"
      />
    </NCard>

    <NCard size="small" title="HTTP 信息">
      <NDescriptions :column="3" bordered size="small" class="mb-3">
        <NDescriptionsItem label="请求方法">
          <span class="font-mono font-bold">{{ httpInfo.method || '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="响应大小">
          <span class="font-mono">
            {{
              httpInfo.content_length != null
                ? `${(httpInfo.content_length / 1024).toFixed(1)} KB`
                : '-'
            }}
          </span>
        </NDescriptionsItem>
        <NDescriptionsItem label="关键词验证">
          <NTag
            v-if="httpInfo.keyword_found != null"
            :type="httpInfo.keyword_found ? 'success' : 'error'"
            size="small"
            :bordered="false"
          >
            {{ httpInfo.keyword_found ? '关键词存在' : '关键词缺失' }}
          </NTag>
          <span v-else class="text-muted-foreground text-xs">未配置</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="最终URL" :span="3">
          <span class="font-mono break-all text-xs">
            {{ httpInfo.final_url || '-' }}
          </span>
        </NDescriptionsItem>
      </NDescriptions>

      <div v-if="(httpInfo.redirect_chain || []).length" class="mb-3">
        <div class="text-muted-foreground mb-1 text-xs">
          重定向链（{{ httpInfo.redirect_chain.length }} 跳）
        </div>
        <NDataTable
          :columns="redirectCols"
          :data="httpInfo.redirect_chain"
          size="small"
          :max-height="200"
        />
      </div>

      <div v-if="respHeaderRows.length">
        <div class="text-muted-foreground mb-1 text-xs">
          响应头（{{ respHeaderRows.length }} 项）
        </div>
        <NDataTable
          :columns="headerCols"
          :data="respHeaderRows"
          size="small"
          :max-height="240"
        />
      </div>

      <div
        v-if="!httpInfo.redirect_chain?.length && !respHeaderRows.length"
        class="text-muted-foreground py-2 text-xs"
      >
        无重定向，无特殊响应头
      </div>
    </NCard>

    <NCard
      v-if="
        ssl.enabled !== undefined ||
        (ssl.errors && ssl.errors.length > 0) ||
        ssl.protocol_version
      "
      size="small"
      title="SSL / TLS 证书"
    >
      <NDescriptions :column="3" bordered size="small">
        <NDescriptionsItem label="SSL启用">
          <NTag :type="ssl.enabled ? 'success' : 'info'" size="small" :bordered="false">
            {{ ssl.enabled ? '是' : '否' }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="证书有效">
          <NTag :type="ssl.is_valid ? 'success' : 'error'" size="small" :bordered="false">
            {{ ssl.is_valid ? '有效' : '无效' }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="剩余有效期">
          <span
            :class="
              (ssl.days_remaining ?? 9999) < 30
                ? 'text-red-500 font-bold'
                : 'text-green-500'
            "
            class="font-mono"
          >
            {{ ssl.days_remaining != null ? `${ssl.days_remaining} 天` : '-' }}
          </span>
        </NDescriptionsItem>
        <NDescriptionsItem label="协议版本">
          <span class="font-mono">{{ ssl.protocol_version || '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="加密套件">
          <span class="font-mono text-xs">{{ ssl.cipher_suite || '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="套件强度">
          <NTag :type="sevTag(ssl.cipher_strength || '')" size="small" :bordered="false">
            {{ sevLabel(ssl.cipher_strength) }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="有效期起">{{ ssl.not_before || '-' }}</NDescriptionsItem>
        <NDescriptionsItem label="有效期止">{{ ssl.not_after || '-' }}</NDescriptionsItem>
        <NDescriptionsItem label="证书链">
          <NTag
            :type="ssl.chain_complete === false ? 'error' : 'success'"
            size="small"
            :bordered="false"
          >
            {{ ssl.chain_complete === false ? '不完整' : '完整' }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="颁发机构" :span="3">
          <span class="text-xs">{{ ssl.issuer || '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="证书主题" :span="3">
          <span class="text-xs">{{ ssl.subject || '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem v-if="(ssl.san || []).length" label="SAN域名" :span="3">
          <span class="text-xs">{{ (ssl.san || []).join(' | ') }}</span>
        </NDescriptionsItem>
      </NDescriptions>
      <div v-if="(ssl.errors || []).length" class="mt-2 space-y-1">
        <div
          v-for="(e, i) in ssl.errors"
          :key="i"
          class="text-error text-xs"
        >
          ⚠ {{ e }}
        </div>
      </div>
    </NCard>

    <NCard
      v-if="(r.security_issues || []).length"
      size="small"
      :title="`安全问题（${r.security_issues.length} 项）`"
    >
      <NDataTable
        :columns="securityIssueCols"
        :data="r.security_issues"
        size="small"
        :max-height="300"
      />
    </NCard>

    <NCard
      v-if="errors.length || warnings.length"
      size="small"
      title="错误与警告"
    >
      <div v-if="errors.length" class="mb-2">
        <div class="text-error mb-1 text-xs font-semibold">
          错误（{{ errors.length }}）
        </div>
        <div
          v-for="(e, i) in errors"
          :key="i"
          class="text-error py-0.5 text-xs"
        >
          ✕ {{ e }}
        </div>
      </div>
      <div v-if="warnings.length">
        <div class="mb-1 text-xs font-semibold text-yellow-500">
          警告（{{ warnings.length }}）
        </div>
        <div
          v-for="(w, i) in warnings"
          :key="i"
          class="py-0.5 text-xs text-yellow-600"
        >
          ⚠ {{ w }}
        </div>
      </div>
    </NCard>
  </div>
</template>
