<script lang="ts" setup>
import { computed } from 'vue';
import { NButton, NCard, NSpace, NTag } from 'naive-ui';

import type { Asset } from '#/api/asset';

defineOptions({ name: 'LedgerExpiryAlerts' });

const props = defineProps<{
  assets: Asset[];
}>();

const emit = defineEmits<{
  detail: [row: Asset];
}>();

const now = new Date();
const thirtyDaysLater = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

function isExpired(date?: string) {
  return date ? new Date(date) < now : false;
}

function isExpiring(date?: string) {
  if (!date) return false;
  const value = new Date(date);
  return value >= now && value <= thirtyDaysLater;
}

function formatDate(date?: string) {
  return date ? date.slice(0, 10) : '';
}

const expiredSslAssets = computed(() => props.assets.filter((item) => isExpired(item.ssl_expires_at)).slice(0, 10));
const expiredDomainAssets = computed(() => props.assets.filter((item) => isExpired(item.domain_expires_at)).slice(0, 10));
const expiringSslAssets = computed(() => props.assets.filter((item) => isExpiring(item.ssl_expires_at)).slice(0, 10));
const expiringDomainAssets = computed(() => props.assets.filter((item) => isExpiring(item.domain_expires_at)).slice(0, 10));

const hasAlerts = computed(() =>
  expiredSslAssets.value.length > 0
  || expiredDomainAssets.value.length > 0
  || expiringSslAssets.value.length > 0
  || expiringDomainAssets.value.length > 0,
);
</script>

<template>
  <NCard v-if="hasAlerts" size="small" class="ledger-expiry-alerts">
    <NSpace vertical :size="8">
      <div v-if="expiredSslAssets.length > 0" class="ledger-expiry-alerts__row">
        <span class="ledger-expiry-alerts__title ledger-expiry-alerts__title--error">
          SSL证书已过期（{{ expiredSslAssets.length }}）
        </span>
        <NSpace wrap :size="4">
          <NTag
            v-for="item in expiredSslAssets"
            :key="item.id"
            size="small"
            type="error"
            class="ledger-expiry-alerts__tag"
            @click="emit('detail', item)"
          >
            {{ item.name || item.address || item.id }}
          </NTag>
        </NSpace>
      </div>

      <div v-if="expiredDomainAssets.length > 0" class="ledger-expiry-alerts__row">
        <span class="ledger-expiry-alerts__title ledger-expiry-alerts__title--error">
          域名已过期（{{ expiredDomainAssets.length }}）
        </span>
        <NSpace wrap :size="4">
          <NTag
            v-for="item in expiredDomainAssets"
            :key="item.id"
            size="small"
            type="error"
            class="ledger-expiry-alerts__tag"
            @click="emit('detail', item)"
          >
            {{ item.name || item.domain || item.address || item.id }}
          </NTag>
        </NSpace>
      </div>

      <div v-if="expiringSslAssets.length > 0" class="ledger-expiry-alerts__row">
        <span class="ledger-expiry-alerts__title ledger-expiry-alerts__title--warning">
          SSL证书即将到期（{{ expiringSslAssets.length }}）
        </span>
        <NSpace wrap :size="4">
          <NTag
            v-for="item in expiringSslAssets"
            :key="item.id"
            size="small"
            type="warning"
            class="ledger-expiry-alerts__tag"
            @click="emit('detail', item)"
          >
            {{ item.name || item.address || item.id }} {{ formatDate(item.ssl_expires_at) }}
          </NTag>
        </NSpace>
      </div>

      <div v-if="expiringDomainAssets.length > 0" class="ledger-expiry-alerts__row">
        <span class="ledger-expiry-alerts__title ledger-expiry-alerts__title--warning">
          域名即将到期（{{ expiringDomainAssets.length }}）
        </span>
        <NSpace wrap :size="4">
          <NTag
            v-for="item in expiringDomainAssets"
            :key="item.id"
            size="small"
            type="warning"
            class="ledger-expiry-alerts__tag"
            @click="emit('detail', item)"
          >
            {{ item.name || item.domain || item.address || item.id }} {{ formatDate(item.domain_expires_at) }}
          </NTag>
        </NSpace>
      </div>
    </NSpace>

    <template #header>
      <div class="ledger-expiry-alerts__header">
        <span>到期提醒</span>
        <NButton size="tiny" text type="primary">查看资产详情处理</NButton>
      </div>
    </template>
  </NCard>
</template>

<style scoped>
.ledger-expiry-alerts__header {
  align-items: center;
  display: flex;
  justify-content: space-between;
  width: 100%;
}

.ledger-expiry-alerts__row {
  align-items: center;
  display: grid;
  gap: 10px;
  grid-template-columns: 150px minmax(0, 1fr);
}

.ledger-expiry-alerts__title {
  font-size: 13px;
  font-weight: 500;
}

.ledger-expiry-alerts__title--error {
  color: var(--n-error-color);
}

.ledger-expiry-alerts__title--warning {
  color: var(--n-warning-color);
}

.ledger-expiry-alerts__tag {
  cursor: pointer;
}

@media (max-width: 720px) {
  .ledger-expiry-alerts__row {
    grid-template-columns: 1fr;
  }
}
</style>
