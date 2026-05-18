<script lang="ts" setup>
import { onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';

defineOptions({ name: 'CircularInputAdd' });

const route = useRoute();
const router = useRouter();

/** 兼容旧链接：重定向到列表页（新建/编辑改由侧边抽屉完成） */
onMounted(() => {
  const id = route.query.id as string | undefined;
  router.replace({
    path: '/circular/input',
    query: id ? { edit: id } : { create: '1' },
  });
});
</script>

<template>
  <div />
</template>
