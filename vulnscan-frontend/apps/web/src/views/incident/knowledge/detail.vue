<script lang="ts" setup>
import { onMounted, ref } from 'vue';
import { NButton, NCard, NDescriptions, NDescriptionsItem, NSpace, NTag, NSpin } from 'naive-ui';
import { useRoute, useRouter } from 'vue-router';
import { getKnowledgeDetail, getKnowledgeRecommend, type KnowledgeArticle } from '#/api/incident';

defineOptions({ name: 'IncidentKnowledgeDetail' });

const route = useRoute();
const router = useRouter();
const loading = ref(true);
const article = ref<KnowledgeArticle | null>(null);
const related = ref<KnowledgeArticle[]>([]);

async function fetchData() {
  try {
    const id = route.params.id as string;
    article.value = await getKnowledgeDetail(id) as any;
    try { related.value = (await getKnowledgeRecommend({ id }) as any) ?? []; } catch { related.value = []; }
  } finally { loading.value = false; }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px;max-width:800px;margin:0 auto">
    <NSpin :show="loading">
      <template v-if="article">
        <NCard size="small" style="margin-bottom:16px">
          <template #header>
            <NSpace align="center" :size="12">
              <NButton text @click="router.back()">← 返回</NButton>
              <span style="font-size:16px;font-weight:600">{{ article.title }}</span>
              <NTag size="small" :bordered="false">{{ article.category || '-' }}</NTag>
            </NSpace>
          </template>
          <NDescriptions label-placement="left" bordered :column="2" size="small" style="margin-bottom:16px">
            <NDescriptionsItem label="作者">{{ article.author || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="浏览量">{{ article.view_count ?? 0 }}</NDescriptionsItem>
            <NDescriptionsItem label="创建时间">{{ article.created_at }}</NDescriptionsItem>
            <NDescriptionsItem label="更新时间">{{ article.updated_at || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="标签" :span="2">
              <NSpace :size="4" v-if="article.tags?.length"><NTag v-for="t in article.tags" :key="t" size="small" type="info" :bordered="false">{{ t }}</NTag></NSpace>
              <span v-else style="color:#ccc">-</span>
            </NDescriptionsItem>
          </NDescriptions>
          <div style="line-height:1.8;font-size:14px;white-space:pre-wrap">{{ article.content }}</div>
        </NCard>
        <NCard title="相关文章" size="small" v-if="related.length">
          <div v-for="r in related" :key="r.id" style="padding:6px 0;border-bottom:1px solid #f0f0f0;cursor:pointer" @click="router.push(`/incident/knowledge/${r.id}`)">
            <span style="color:#2080f0">{{ r.title }}</span>
            <NTag size="tiny" :bordered="false" style="margin-left:8px">{{ r.category }}</NTag>
          </div>
        </NCard>
      </template>
    </NSpin>
  </div>
</template>
