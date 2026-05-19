<script lang="ts" setup>
import type { DimensionConfig, FileLibrary } from '#/api/sitemonitor';

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
}>();

function getField(dim: string, field: string, fallback: any = undefined) {
  return props.configs[dim]?.[field] ?? fallback;
}

function setField(dim: string, field: string, val: any) {
  if (!props.configs[dim]) props.configs[dim] = {};
  props.configs[dim][field] = val;
}

function setCycleMinutes(dim: string, minutes: number | null) {
  const m = Math.max(1, Math.min(1440, minutes || 1));
  setField(dim, 'cycle_minutes', m);
  const cronMin = m > 59 ? 59 : m;
  setField(dim, 'cron', `0 */${cronMin} * * * *`);
  const c = props.configs[dim];
  if (c) {
    delete c.cycle_type;
    delete c.cycle_time;
    delete c.run_once;
  }
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
  <div class="dim-form">
    <section
      v-for="dim in dimensions"
      :key="dim.key"
      class="dim-card"
    >
      <div class="dim-card__head">
        <span class="dim-card__title">{{ dim.label }}</span>
        <label class="dim-inline">
          <span class="dim-inline__label">监测开关</span>
          <NSwitch
            :value="getField(dim.key, 'enabled', false)"
            size="small"
            @update:value="(v: boolean) => setField(dim.key, 'enabled', v)"
          />
        </label>
        <label class="dim-inline">
          <span class="dim-inline__label">发送告警</span>
          <NSwitch
            :value="getField(dim.key, 'alert_enabled', false)"
            size="small"
            @update:value="(v: boolean) => setField(dim.key, 'alert_enabled', v)"
          />
        </label>
      </div>

      <div class="dim-card__body">
        <!-- 固定周期：可用性 / 篡改 / 域名劫持 -->
        <div
          v-if="['availability', 'domain_hijack', 'tamper'].includes(dim.key)"
          class="dim-row"
        >
          <label class="dim-inline">
            <span class="dim-inline__label">周期</span>
            <NInputNumber
              :value="getField(dim.key, 'cycle_minutes', 1)"
              :min="1"
              :max="1440"
              size="small"
              class="dim-num"
              @update:value="(v: null | number) => setCycleMinutes(dim.key, v)"
            />
            <span class="dim-inline__suffix">分钟/次</span>
          </label>

          <label v-if="dim.key === 'availability'" class="dim-inline">
            <span class="dim-inline__label">访问超时</span>
            <NInputNumber
              :value="getField(dim.key, 'timeout_seconds', 60)"
              :min="5"
              :max="300"
              size="small"
              class="dim-num dim-num--sm"
              @update:value="
                (v: null | number) => setField(dim.key, 'timeout_seconds', v ?? 60)
              "
            />
            <span class="dim-inline__suffix">秒</span>
          </label>

          <label v-if="dim.key === 'tamper'" class="dim-inline">
            <span class="dim-inline__label">搜索引擎 UA</span>
            <NSwitch
              :value="getField(dim.key, 'search_engine_ua', false)"
              size="small"
              @update:value="
                (v: boolean) => setField(dim.key, 'search_engine_ua', v)
              "
            />
          </label>
        </div>

        <!-- 可用性：免检时段单独一行 -->
        <div v-if="dim.key === 'availability'" class="dim-row">
          <label class="dim-inline">
            <span class="dim-inline__label">免检时段</span>
            <NSwitch
              :value="getField(dim.key, 'exclude_time_enabled', false)"
              size="small"
              @update:value="
                (v: boolean) => setField(dim.key, 'exclude_time_enabled', v)
              "
            />
          </label>
          <template v-if="getField(dim.key, 'exclude_time_enabled', false)">
            <label class="dim-inline">
              <NTimePicker
                :formatted-value="getField(dim.key, 'exclude_time_start', '00:00')"
                format="HH:mm"
                size="small"
                class="dim-time"
                @update:formatted-value="
                  (v: null | string) =>
                    setField(dim.key, 'exclude_time_start', v ?? '00:00')
                "
              />
              <span class="dim-inline__suffix">至</span>
              <NTimePicker
                :formatted-value="getField(dim.key, 'exclude_time_end', '06:00')"
                format="HH:mm"
                size="small"
                class="dim-time"
                @update:formatted-value="
                  (v: null | string) =>
                    setField(dim.key, 'exclude_time_end', v ?? '06:00')
                "
              />
            </label>
          </template>
        </div>

        <!-- 敏感词 / 黑链 -->
        <div
          v-if="['sensitive_word', 'blacklink'].includes(dim.key)"
          class="dim-row"
        >
          <label class="dim-inline">
            <span class="dim-inline__label">周期</span>
            <NInputNumber
              :value="getField(dim.key, 'cycle_minutes', 1)"
              :min="1"
              :max="1440"
              size="small"
              class="dim-num"
              @update:value="(v: null | number) => setCycleMinutes(dim.key, v)"
            />
            <span class="dim-inline__suffix">分钟/次</span>
          </label>
          <span v-if="dim.key === 'sensitive_word'" class="dim-hint">
            词库：自动使用系统敏感词库
          </span>
        </div>

        <!-- 敏感文件（目标级） -->
        <template v-if="dim.key === 'sensitive_file'">
          <div class="dim-row">
            <label class="dim-inline">
              <span class="dim-inline__label">周期</span>
              <NSelect
                :value="getField(dim.key, 'cycle_type', 'daily')"
                :options="cycleTypeOptions"
                size="small"
                class="dim-select"
                @update:value="(v: string) => setField(dim.key, 'cycle_type', v)"
              />
            </label>
            <label class="dim-inline">
              <span class="dim-inline__label">执行时间</span>
              <NTimePicker
                :formatted-value="getField(dim.key, 'cycle_time', '02:00')"
                format="HH:mm"
                size="small"
                class="dim-time"
                @update:formatted-value="
                  (v: null | string) => setField(dim.key, 'cycle_time', v ?? '02:00')
                "
              />
            </label>
            <label class="dim-inline">
              <span class="dim-inline__label">仅运行一次</span>
              <NSwitch
                :value="getField(dim.key, 'run_once', false)"
                size="small"
                @update:value="(v: boolean) => setField(dim.key, 'run_once', v)"
              />
            </label>
          </div>
          <div class="dim-row">
            <label class="dim-inline dim-inline--grow">
              <span class="dim-inline__label">文件库</span>
              <NSelect
                :value="getField(dim.key, 'file_library_ids', [])"
                multiple
                max-tag-count="responsive"
                placeholder="请选择文件库"
                size="small"
                class="dim-select--wide"
                :options="
                  fileLibraries.map((lib) => ({
                    label: lib.name,
                    value: lib.id,
                  }))
                "
                @update:value="(v: string[]) => setField(dim.key, 'file_library_ids', v)"
              />
            </label>
          </div>
        </template>
      </div>
    </section>
  </div>
</template>

<style scoped>
.dim-form {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.dim-card {
  border: 1px solid var(--n-border-color);
  border-radius: 6px;
  padding: 10px 12px;
}

.dim-card__head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 12px 20px;
}

.dim-card__title {
  flex: 0 0 auto;
  min-width: 56px;
  font-weight: 500;
  font-size: 14px;
}

.dim-card__body {
  margin-top: 10px;
  padding-top: 10px;
  border-top: 1px dashed var(--n-border-color);
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.dim-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px 16px;
}

/* 标签与控件成组，避免换行拆开 */
.dim-inline {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
  white-space: nowrap;
  cursor: default;
}

.dim-inline--grow {
  flex: 1 1 100%;
  min-width: 0;
  white-space: normal;
}

.dim-inline__label {
  flex-shrink: 0;
  font-size: 12px;
  color: var(--n-text-color-3);
}

.dim-inline__suffix {
  flex-shrink: 0;
  font-size: 12px;
  color: var(--n-text-color-3);
}

.dim-num {
  width: 88px;
}

.dim-num--sm {
  width: 72px;
}

.dim-time {
  width: 96px;
}

.dim-select {
  width: 112px;
}

.dim-select--wide {
  flex: 1;
  min-width: 160px;
}

.dim-hint {
  font-size: 12px;
  color: var(--n-text-color-3);
}
</style>
