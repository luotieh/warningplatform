<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { NAlert, NModal, NSpin } from 'naive-ui';
import { deepflowGetOccurrences } from '#/api/ly/deepflow';

const props = defineProps<{ eventId: string; hitId: string; visible: boolean; version?: number }>();
const emit = defineEmits<{ (event: 'update:visible', value: boolean): void }>();
const loading = ref(false);
const error = ref('');
const evidence = ref<Record<string, any>>({});
let request = 0;
watch(() => [props.visible, props.eventId, props.hitId, props.version], async () => {
  const current = ++request;
  if (!props.visible || !props.hitId) return;
  loading.value = true;
  error.value = '';
  evidence.value = {};
  try {
    const page = await deepflowGetOccurrences(props.eventId, '', props.hitId, props.version || 0);
    if (current === request) evidence.value = page.items[0] || {};
  } catch (e) {
    if (current === request) error.value = e instanceof Error ? e.message : '证据读取失败';
  } finally {
    if (current === request) loading.value = false;
  }
});

// 抓获报文（packet_hex）以 hexdump 展示；采集内容可能已截断。
// 与抓包工具一致：偏移 + 十六进制 + ASCII。
const packetBytes = computed(() => {
  const clean = String(evidence.value.packet_hex || '').replace(/[^0-9a-fA-F]/g, '');
  return Math.floor(clean.length / 2);
});

const packetDump = computed(() => {
  const clean = String(evidence.value.packet_hex || '').replace(/[^0-9a-fA-F]/g, '');
  const bytes: number[] = [];
  for (let i = 0; i + 1 < clean.length; i += 2) {
    bytes.push(Number.parseInt(clean.slice(i, i + 2), 16));
  }
  const lines: string[] = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const chunk = bytes.slice(off, off + 16);
    const hexPart = chunk.map((b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
    const ascii = chunk.map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${off.toString(16).padStart(8, '0')}  ${hexPart}  ${ascii}`);
  }
  return lines.join('\n');
});
</script>

<template>
  <NModal :show="visible" preset="card" title="关键证据 · 原始命中明细" style="width:900px;max-width:95vw" @update:show="emit('update:visible', $event)">
    <NSpin :show="loading">
      <NAlert v-if="error" type="warning">{{ error }}</NAlert>
      <template v-else>
        <div>事件：{{ eventId }}</div>
        <div style="overflow-wrap:anywhere">明细 ID：{{ hitId }}</div>
        <div v-if="evidence.payload_text" class="evidence-section">
          <div class="evidence-section-title">报文明文</div>
          <pre class="evidence-block">{{ evidence.payload_text }}</pre>
        </div>
        <NAlert v-if="evidence.capture_truncated || (evidence.wire_length && packetBytes < Number(evidence.wire_length))" type="warning" class="evidence-section">
          当前命中包未完整保存，以下仅展示已抓获的字节。
        </NAlert>
        <NAlert v-if="evidence.exchange?.response?.truncated || evidence.exchange?.response?.reassembly_incomplete" type="warning" class="evidence-section">
          响应证据存在截断或 TCP 重组缺口，不能视为完整响应。
        </NAlert>
        <div v-if="evidence.exchange?.response_status === 'partial'" class="evidence-section">
          响应完整性：不完整或应用消息边界尚未核验。
        </div>
        <div v-if="evidence.packet_hex" class="evidence-section">
          <div class="evidence-section-title">抓获报文（packet_hex · {{ packetBytes }} 字节）</div>
          <pre class="evidence-block evidence-hex">{{ packetDump }}</pre>
        </div>
        <div class="evidence-section-title">原始明细 JSON</div>
        <pre style="max-height:65vh;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere">{{ JSON.stringify(evidence, null, 2) }}</pre>
      </template>
    </NSpin>
  </NModal>
</template>

<style scoped>
.evidence-section {
  margin: 12px 0;
}

.evidence-section-title {
  margin: 12px 0 6px;
  font-size: 13px;
  font-weight: 600;
  color: #333;
}

.evidence-block {
  max-height: 40vh;
  padding: 8px 10px;
  margin: 0;
  overflow: auto;
  font-family: Consolas, Monaco, monospace;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: #f7f8fa;
  border-radius: 6px;
}

.evidence-hex {
  white-space: pre;
  overflow-wrap: normal;
}
</style>
