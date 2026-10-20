<script setup lang="ts">
import { computed } from 'vue';

import { NPopover } from 'naive-ui';

import { assetMatchesEvent, normalizeAddr } from '#/utils/ly-asset';

const props = withDefaults(defineProps<{
  address: string;
  row: Record<string, any>;
  assets?: Record<string, any>[];
}>(), { assets: () => [] });

function text(value: unknown): string {
  if (Array.isArray(value)) return value.map(text).filter(Boolean).join('、');
  return typeof value === 'string' || typeof value === 'number' ? String(value).trim() : '';
}

const matchingAssets = computed(() => props.assets.filter(
  (asset) => asset.status === 1 && assetMatchesEvent(asset, { attackDevice: props.address }),
));

// IOC 情报仅绑定其自身地址，不将域名情报套在 DNS 解析器或其他通联 IP 上。
const matchingIOC = computed(() => {
  const ioc = props.row.ioc;
  const canonical = (value: string) => normalizeAddr(value).replace(/\.$/, '');
  const matches = ioc?.ioc_type === 'domain'
    ? canonical(text(ioc.ioc_value)) === canonical(props.address)
    : normalizeAddr(text(ioc?.ioc_value)) === normalizeAddr(props.address);
  return matches ? ioc : null;
});

const iocFields = computed(() => {
  const ioc = matchingIOC.value;
  if (!ioc) return [];
  const evidence = props.row.ioc_evidence || {};
  return [
    ['名称', text(ioc.ioc_name || ioc.name)],
    ['情报来源', text(ioc.ioc_source)],
    ['威胁类别', text(ioc.ioc_category)],
    ['情报简述', text(ioc.ioc_description) || text(evidence.activity)],
    ['威胁标签', text(evidence.threat_labels) || text(ioc.ioc_tags)],
    ['情报置信度', text(evidence.confidence)],
  ].filter(([, value]) => value);
});

const hasAddress = computed(() => Boolean(props.address && props.address !== '-'));
</script>

<template>
  <NPopover
    v-if="hasAddress"
    trigger="hover"
    placement="top"
    :delay="200"
    :style="{ width: '320px', maxWidth: 'calc(100vw - 32px)' }"
  >
    <template #trigger>
      <span class="address-summary-trigger" tabindex="0"><slot>{{ address }}</slot></span>
    </template>
    <div class="address-summary">
      <div class="summary-address">{{ address }}</div>
      <section v-for="asset in matchingAssets.slice(0, 3)" :key="asset.id || asset.address" class="summary-section">
        <div class="summary-heading">资产 · {{ asset.name || '未命名资产' }}</div>
        <div v-if="normalizeAddr(asset.address) !== normalizeAddr(address)" class="summary-field">
          <span>登记地址</span><span>{{ asset.address }}</span>
        </div>
        <div v-if="asset.unit" class="summary-field"><span>所属单位</span><span>{{ asset.unit }}</span></div>
        <div v-if="asset.owner" class="summary-field"><span>负责人</span><span>{{ asset.owner }}</span></div>
        <div v-if="asset.remark" class="summary-field"><span>资产备注</span><span class="summary-excerpt">{{ asset.remark }}</span></div>
      </section>
      <div v-if="matchingAssets.length > 3" class="summary-muted">另匹配 {{ matchingAssets.length - 3 }} 项资产登记</div>
      <section v-if="matchingIOC" class="summary-section">
        <div class="summary-heading">IOC 情报 · {{ matchingIOC.ioc_type || 'IOC' }}</div>
        <div v-for="[label, value] in iocFields" :key="label" class="summary-field">
          <span>{{ label }}</span><span class="summary-excerpt">{{ value }}</span>
        </div>
        <div v-if="!iocFields.length" class="summary-muted">当前事件未提供情报摘要</div>
        <div class="summary-muted">右键 IOC 标签可查看历史事件</div>
      </section>
      <div v-if="!matchingAssets.length && !matchingIOC" class="summary-muted">当前列表未提供该地址的资产或情报摘要</div>
    </div>
  </NPopover>
  <slot v-else>{{ address || '-' }}</slot>
</template>

<style scoped>
.address-summary-trigger { display: inline-flex; max-width: 100%; cursor: help; }
.address-summary { font-family: var(--font-family, sans-serif); font-size: 12px; line-height: 1.6; overflow-wrap: anywhere; }
.summary-address { font-family: ui-monospace, monospace; font-size: 13px; font-weight: 600; }
.summary-section { margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--n-divider-color); }
.summary-heading { margin-bottom: 4px; font-weight: 600; }
.summary-field { display: grid; grid-template-columns: 72px minmax(0, 1fr); gap: 8px; margin-top: 3px; }
.summary-field > span:first-child, .summary-muted { color: var(--n-text-color-disabled); }
.summary-muted { margin-top: 5px; }
.summary-excerpt { display: -webkit-box; overflow: hidden; -webkit-box-orient: vertical; -webkit-line-clamp: 3; }
</style>
