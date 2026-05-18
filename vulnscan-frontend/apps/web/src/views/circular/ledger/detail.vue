<script lang="ts" setup>
import { onMounted, ref } from 'vue';
import { NSpin } from 'naive-ui';
import { useRoute, useRouter } from 'vue-router';

import type { DynamicFormTemplate } from '#/api/formdesign';
import { getDynamicFormTemplate } from '#/api/formdesign';
import {
  getLedgerDetail,
  getCircularOplogs,
  type CircularDetailResp,
  type CircularOplog,
} from '#/api/circular';
import CircularDetailPanel from '../components/circular-detail-panel.vue';

defineOptions({ name: 'CircularLedgerDetail' });

const route = useRoute();
const router = useRouter();
const loading = ref(true);
const detail = ref<CircularDetailResp | null>(null);
const oplogs = ref<CircularOplog[]>([]);
const template = ref<DynamicFormTemplate | null>(null);

async function fetchData() {
  try {
    const id = route.params.id as string;
    detail.value = (await getLedgerDetail(id)) as unknown as CircularDetailResp;

    if (detail.value?.circular_template) {
      try {
        template.value = await getDynamicFormTemplate(detail.value.circular_template);
      } catch {
        template.value = null;
      }
    }

    try {
      oplogs.value = ((await getCircularOplogs(id)) as unknown as CircularOplog[]) ?? [];
    } catch {
      oplogs.value = [];
    }
  } finally {
    loading.value = false;
  }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding: 16px">
    <NSpin :show="loading">
      <CircularDetailPanel
        v-if="detail"
        :detail="detail"
        :oplogs="oplogs"
        :template="template"
        @back="router.back()"
      />
    </NSpin>
  </div>
</template>
