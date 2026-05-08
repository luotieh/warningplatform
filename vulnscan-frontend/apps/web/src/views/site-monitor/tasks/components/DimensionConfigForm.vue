<script lang="ts" setup>
import type {
  DimensionConfig,
  FileLibrary,
  WordLibrary,
} from '#/api/monitor';

import {
  NInputNumber,
  NSelect,
  NSwitch,
  NTimePicker,
} from 'naive-ui';

interface DimensionMeta {
  key: string;
  label: string;
}

const props = defineProps<{
  configs: Record<string, DimensionConfig>;
  dimensions: DimensionMeta[];
  fileLibraries: FileLibrary[];
  wordLibraries: WordLibrary[];
}>();

function getField(dim: string, field: string, fallback: any = undefined) {
  return props.configs[dim]?.[field] ?? fallback;
}

function setField(dim: string, field: string, val: any) {
  if (!props.configs[dim]) props.configs[dim] = {};
  props.configs[dim][field] = val;
}

const cycleTypeOptions = [
  { label: '每天', value: 'daily' },
  { label: '每周一次', value: 'weekly' },
  { label: '每月一次', value: 'monthly' },
  { label: '每季一次', value: 'quarterly' },
  { label: '半年一次', value: 'semi_annual' },
];
</script>

<template>
  <div class="space-y-4">
    <div
      v-for="dim in dimensions"
      :key="dim.key"
      class="rounded border p-3"
    >
      <div class="mb-2 flex items-center gap-4">
        <span class="w-[80px] font-medium">{{ dim.label }}</span>
        <div class="flex items-center gap-1">
          <span class="text-muted-foreground text-xs">监测开关</span>
          <NSwitch
            :value="getField(dim.key, 'enabled', false)"
            @update:value="(v: boolean) => setField(dim.key, 'enabled', v)"
          />
        </div>
        <div class="flex items-center gap-1">
          <span class="text-muted-foreground text-xs">发送告警</span>
          <NSwitch
            :value="getField(dim.key, 'alert_enabled', false)"
            @update:value="
              (v: boolean) => setField(dim.key, 'alert_enabled', v)
            "
          />
        </div>
      </div>

      <div
        class="ml-[84px] flex flex-wrap items-center gap-3 text-sm"
      >
        <template
          v-if="
            ['availability', 'domain_hijack', 'tamper'].includes(dim.key)
          "
        >
          <span class="text-muted-foreground">周　期：</span>
          <NInputNumber
            :value="getField(dim.key, 'cycle_minutes', 5)"
            :min="1"
            :max="1440"
            size="small"
            style="width: 100px"
            @update:value="
              (v: null | number) =>
                setField(dim.key, 'cycle_minutes', v ?? 5)
            "
          />
          <span class="text-muted-foreground">分钟/次</span>
        </template>

        <template v-if="dim.key === 'availability'">
          <span class="text-muted-foreground ml-4">访问超时：</span>
          <NInputNumber
            :value="getField(dim.key, 'timeout_seconds', 60)"
            :min="5"
            :max="300"
            size="small"
            style="width: 100px"
            @update:value="
              (v: null | number) =>
                setField(dim.key, 'timeout_seconds', v ?? 60)
            "
          />
          <span class="text-muted-foreground">秒</span>
          <span class="text-muted-foreground ml-4">免检时段：</span>
          <NSwitch
            :value="getField(dim.key, 'exclude_time_enabled', false)"
            size="small"
            @update:value="
              (v: boolean) =>
                setField(dim.key, 'exclude_time_enabled', v)
            "
          />
          <template v-if="getField(dim.key, 'exclude_time_enabled', false)">
            <NTimePicker
              :formatted-value="
                getField(dim.key, 'exclude_time_start', '00:00')
              "
              format="HH:mm"
              size="small"
              style="width: 100px"
              @update:formatted-value="
                (v: null | string) =>
                  setField(dim.key, 'exclude_time_start', v ?? '00:00')
              "
            />
            <span class="text-muted-foreground">至</span>
            <NTimePicker
              :formatted-value="
                getField(dim.key, 'exclude_time_end', '06:00')
              "
              format="HH:mm"
              size="small"
              style="width: 100px"
              @update:formatted-value="
                (v: null | string) =>
                  setField(dim.key, 'exclude_time_end', v ?? '06:00')
              "
            />
          </template>
        </template>

        <template v-if="dim.key === 'tamper'">
          <span class="text-muted-foreground ml-4">搜索引擎UA</span>
          <NSwitch
            :value="getField(dim.key, 'search_engine_ua', false)"
            size="small"
            @update:value="
              (v: boolean) => setField(dim.key, 'search_engine_ua', v)
            "
          />
        </template>

        <template
          v-if="
            ['blacklink', 'sensitive_file', 'sensitive_word'].includes(
              dim.key,
            )
          "
        >
          <span class="text-muted-foreground">周　期：</span>
          <NSelect
            :value="getField(dim.key, 'cycle_type', 'daily')"
            :options="cycleTypeOptions"
            size="small"
            style="width: 120px"
            @update:value="
              (v: string) => setField(dim.key, 'cycle_type', v)
            "
          />
          <NTimePicker
            :formatted-value="getField(dim.key, 'cycle_time', '02:00')"
            format="HH:mm"
            size="small"
            style="width: 100px"
            @update:formatted-value="
              (v: null | string) =>
                setField(dim.key, 'cycle_time', v ?? '02:00')
            "
          />
          <span class="text-muted-foreground ml-2">仅运行一次</span>
          <NSwitch
            :value="getField(dim.key, 'run_once', false)"
            size="small"
            @update:value="
              (v: boolean) => setField(dim.key, 'run_once', v)
            "
          />
        </template>

        <template v-if="dim.key === 'sensitive_word'">
          <span class="text-muted-foreground ml-4">词库：</span>
          <NSelect
            :value="getField(dim.key, 'word_library_ids', [])"
            multiple
            max-tag-count="responsive"
            placeholder="请选择词库"
            size="small"
            style="width: 320px"
            :options="
              wordLibraries.map((lib) => ({
                label: lib.name,
                value: lib.id,
              }))
            "
            @update:value="
              (v: string[]) =>
                setField(dim.key, 'word_library_ids', v)
            "
          />
        </template>

        <template v-if="dim.key === 'sensitive_file'">
          <span class="text-muted-foreground ml-4">文件库：</span>
          <NSelect
            :value="getField(dim.key, 'file_library_ids', [])"
            multiple
            max-tag-count="responsive"
            placeholder="请选择文件库"
            size="small"
            style="width: 320px"
            :options="
              fileLibraries.map((lib) => ({
                label: lib.name,
                value: lib.id,
              }))
            "
            @update:value="
              (v: string[]) =>
                setField(dim.key, 'file_library_ids', v)
            "
          />
        </template>
      </div>
    </div>
  </div>
</template>
