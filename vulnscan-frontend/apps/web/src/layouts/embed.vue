<script lang="ts" setup>
import { RouterView } from 'vue-router';
</script>

<template>
  <div class="embed-layout">
    <RouterView />
  </div>
</template>

<style scoped>
.embed-layout {
  height: 100vh;
  overflow: auto;
  background: var(--background, #fff);
}
</style>
