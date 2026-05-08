<script lang="ts" setup>
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';

import * as monaco from 'monaco-editor';

const props = withDefaults(
  defineProps<{
    modelValue: string;
    readonly?: boolean;
    height?: string;
  }>(),
  { readonly: false, height: '500px' },
);

const emit = defineEmits<{
  (e: 'update:modelValue', value: string): void;
  (e: 'validate', markers: { message: string; line: number }[]): void;
}>();

const container = ref<HTMLDivElement>();
let editor: monaco.editor.IStandaloneCodeEditor | null = null;

onMounted(() => {
  if (!container.value) return;

  editor = monaco.editor.create(container.value, {
    value: props.modelValue,
    language: 'yaml',
    theme: 'vs-dark',
    readOnly: props.readonly,
    minimap: { enabled: false },
    fontSize: 13,
    lineNumbers: 'on',
    scrollBeyondLastLine: false,
    wordWrap: 'on',
    tabSize: 2,
    automaticLayout: true,
    renderValidationDecorations: 'on',
    padding: { top: 8, bottom: 8 },
    scrollbar: { verticalScrollbarSize: 8, horizontalScrollbarSize: 8 },
  });

  editor.onDidChangeModelContent(() => {
    const val = editor?.getValue() ?? '';
    emit('update:modelValue', val);
  });

  monaco.editor.onDidChangeMarkers((uris) => {
    const uri = uris[0];
    if (!editor || !uri) return;
    const model = editor.getModel();
    if (!model || model.uri.toString() !== uri.toString()) return;
    const markers = monaco.editor.getModelMarkers({ resource: uri });
    emit(
      'validate',
      markers.map((m) => ({
        message: m.message,
        line: m.startLineNumber,
      })),
    );
  });
});

watch(
  () => props.modelValue,
  (val) => {
    if (editor && editor.getValue() !== val) {
      editor.setValue(val);
    }
  },
);

watch(
  () => props.readonly,
  (val) => {
    editor?.updateOptions({ readOnly: val });
  },
);

onBeforeUnmount(() => {
  editor?.dispose();
  editor = null;
});

function setMarkers(
  markers: {
    message: string;
    startLine: number;
    endLine: number;
    severity: 'error' | 'warning';
  }[],
) {
  if (!editor) return;
  const model = editor.getModel();
  if (!model) return;
  monaco.editor.setModelMarkers(
    model,
    'poc-validator',
    markers.map((m) => ({
      startLineNumber: m.startLine,
      startColumn: 1,
      endLineNumber: m.endLine,
      endColumn: model.getLineMaxColumn(m.endLine),
      message: m.message,
      severity:
        m.severity === 'error'
          ? monaco.MarkerSeverity.Error
          : monaco.MarkerSeverity.Warning,
    })),
  );
}

function clearMarkers() {
  if (!editor) return;
  const model = editor.getModel();
  if (!model) return;
  monaco.editor.setModelMarkers(model, 'poc-validator', []);
}

defineExpose({ setMarkers, clearMarkers });
</script>

<template>
  <div ref="container" :style="{ height, width: '100%', borderRadius: '8px', overflow: 'hidden' }" />
</template>
