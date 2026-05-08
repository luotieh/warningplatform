<script setup lang="ts">
import { ref, computed, h, onMounted } from 'vue';
import {
  NCard, NInput, NButton, NSpace, NSelect, NDataTable, NTag,
  NDrawer, NDrawerContent, NDescriptions, NDescriptionsItem,
  NSpin, NEmpty, NInputNumber, useMessage, NGrid, NGridItem,
  NStatistic,
} from 'naive-ui';
import type { DataTableColumns } from 'naive-ui';
import {
  searchCyberspace, hostLookup, getProviders,
  type CyberAsset, type CyberProvider,
} from '#/api/cyberspace';

const message = useMessage();
const loading = ref(false);
const query = ref('');
const mode = ref<'search' | 'host'>('search');
const provider = ref('');
const maxResults = ref(100);
const results = ref<CyberAsset[]>([]);
const total = ref(0);
const providers = ref<CyberProvider[]>([]);

onMounted(async () => {
  try {
    const res = await getProviders();
    providers.value = (res as unknown as CyberProvider[]) ?? [];
  } catch {}
});

const providerOptions = computed(() => [
  { label: '全部平台', value: '' },
  ...providers.value.map(p => ({
    label: `${p.name} ${p.enabled ? '' : '(未配置)'}`,
    value: p.name,
    disabled: !p.enabled,
  })),
]);

async function handleSearch() {
  if (!query.value.trim()) { message.warning('请输入搜索关键词'); return; }

  loading.value = true;
  try {
    if (mode.value === 'host') {
      const res = await hostLookup(query.value.trim());
      results.value = res.items;
      total.value = res.total;
    } else {
      const res = await searchCyberspace({
        q: query.value.trim(),
        provider: provider.value || undefined,
        max: maxResults.value,
      });
      results.value = res.items;
      total.value = res.total;
    }
    message.success(`找到 ${total.value} 条结果`);
  } catch (e: any) {
    message.error('搜索失败: ' + (e?.message || ''));
  } finally {
    loading.value = false;
  }
}

const stats = computed(() => {
  const ips = new Set(results.value.map(a => a.ip));
  const services = new Set(results.value.filter(a => a.service).map(a => a.service));
  const countries = new Set(results.value.filter(a => a.country).map(a => a.country));
  return { ips: ips.size, services: services.size, countries: countries.size, total: results.value.length };
});

const columns: DataTableColumns<CyberAsset> = [
  { title: 'IP', key: 'ip', width: 140 },
  { title: '端口', key: 'port', width: 70 },
  { title: '协议', key: 'protocol', width: 80 },
  {
    title: '服务', key: 'service', width: 100,
    render: (row) => h(NTag, { size: 'small', type: 'info', bordered: false }, () => row.service || '-'),
  },
  { title: '版本', key: 'version', width: 120, ellipsis: { tooltip: true } },
  { title: '标题', key: 'title', width: 200, ellipsis: { tooltip: true } },
  { title: '操作系统', key: 'os', width: 100, ellipsis: { tooltip: true } },
  { title: '国家', key: 'country', width: 80 },
  { title: '组织', key: 'org', width: 140, ellipsis: { tooltip: true } },
  {
    title: '来源', key: 'source', width: 100,
    render: (row) => h(NTag, { size: 'tiny', bordered: false }, () => row.source),
  },
  {
    title: '操作', key: 'actions', width: 80, fixed: 'right',
    render: (row) => h(NButton, { size: 'tiny', quaternary: true, type: 'info', onClick: () => openDetail(row) }, () => '详情'),
  },
];

const detailVisible = ref(false);
const detailItem = ref<CyberAsset | null>(null);

function openDetail(row: CyberAsset) {
  detailItem.value = row;
  detailVisible.value = true;
}
</script>

<template>
  <div class="p-4">
    <NCard title="网络空间搜索" size="small">
      <template #header-extra>
        <NSpace :size="8" align="center">
          <NSelect v-model:value="mode" size="small" style="width:110px" :options="[
            { label: '关键词搜索', value: 'search' },
            { label: 'IP 查询', value: 'host' },
          ]" />
          <NSelect v-if="mode === 'search'" v-model:value="provider" size="small" :options="providerOptions" style="width:140px" />
          <NInputNumber v-if="mode === 'search'" v-model:value="maxResults" size="small" :min="10" :max="1000" :step="50" style="width:100px" />
          <NInput v-model:value="query" size="small" :placeholder="mode === 'host' ? '输入 IP 地址' : '输入搜索语法 (如 domain=example.com)'" style="width:360px" @keyup.enter="handleSearch" />
          <NButton size="small" type="primary" :loading="loading" @click="handleSearch">搜索</NButton>
        </NSpace>
      </template>

      <!-- Stats -->
      <NGrid v-if="results.length" :cols="4" :x-gap="12" style="margin-bottom:12px">
        <NGridItem>
          <NCard size="small" :bordered="false" style="background:var(--card-color)">
            <NStatistic label="结果数" :value="stats.total" />
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard size="small" :bordered="false" style="background:var(--card-color)">
            <NStatistic label="独立IP" :value="stats.ips" />
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard size="small" :bordered="false" style="background:var(--card-color)">
            <NStatistic label="服务类型" :value="stats.services" />
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard size="small" :bordered="false" style="background:var(--card-color)">
            <NStatistic label="国家/地区" :value="stats.countries" />
          </NCard>
        </NGridItem>
      </NGrid>

      <NSpin :show="loading">
        <NDataTable
          v-if="results.length || loading"
          :columns="columns" :data="results" size="small"
          :scroll-x="1300" :bordered="false"
          :pagination="{ pageSize: 50, showSizePicker: true, pageSizes: [20, 50, 100] }"
        />
        <NEmpty v-else description="输入搜索语法查询网络空间数据" style="padding:60px 0" />
      </NSpin>
    </NCard>

    <!-- Detail Drawer -->
    <NDrawer v-model:show="detailVisible" width="520">
      <NDrawerContent v-if="detailItem" :title="`${detailItem.ip}:${detailItem.port}`">
        <NDescriptions label-placement="left" :column="1" bordered size="small">
          <NDescriptionsItem label="IP">{{ detailItem.ip }}</NDescriptionsItem>
          <NDescriptionsItem label="端口">{{ detailItem.port }}</NDescriptionsItem>
          <NDescriptionsItem label="协议">{{ detailItem.protocol }}</NDescriptionsItem>
          <NDescriptionsItem label="服务">{{ detailItem.service || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="版本">{{ detailItem.version || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="标题">{{ detailItem.title || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="操作系统">{{ detailItem.os || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="主机名">{{ detailItem.hostname || '-' }}</NDescriptionsItem>
          <NDescriptionsItem v-if="detailItem.domains?.length" label="域名">
            <NSpace :size="4">
              <NTag v-for="d in detailItem.domains" :key="d" size="small">{{ d }}</NTag>
            </NSpace>
          </NDescriptionsItem>
          <NDescriptionsItem label="国家">{{ detailItem.country || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="城市">{{ detailItem.city || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="ASN">{{ detailItem.asn || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="组织">{{ detailItem.org || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="ISP">{{ detailItem.isp || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="来源">{{ detailItem.source }}</NDescriptionsItem>
          <NDescriptionsItem v-if="detailItem.cert" label="证书主体">{{ detailItem.cert.subject }}</NDescriptionsItem>
          <NDescriptionsItem v-if="detailItem.cert" label="证书颁发者">{{ detailItem.cert.issuer }}</NDescriptionsItem>
          <NDescriptionsItem v-if="detailItem.tags?.length" label="标签">
            <NSpace :size="4">
              <NTag v-for="t in detailItem.tags" :key="t" size="tiny" type="info">{{ t }}</NTag>
            </NSpace>
          </NDescriptionsItem>
        </NDescriptions>

        <div v-if="detailItem.banner" style="margin-top:16px">
          <h4 style="margin:0 0 8px;font-size:13px">Banner</h4>
          <pre style="background:var(--code-color);padding:12px;border-radius:6px;font-size:12px;overflow:auto;max-height:300px">{{ detailItem.banner }}</pre>
        </div>
      </NDrawerContent>
    </NDrawer>
  </div>
</template>
