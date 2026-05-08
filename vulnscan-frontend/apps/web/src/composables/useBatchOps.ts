/**
 * 通用批量操作执行器
 *
 * 后端通常没有"批量删除/批量更新"的专用接口，
 * 这里把"对一批 ID 顺序/并发调用单条接口"统一成一个 composable，
 * 提供：
 *   - 进度回调（已完成 / 总数）
 *   - 成功 / 失败计数
 *   - 错误聚合（包含 id + 错误信息）
 *   - 可控并发（concurrency）
 *   - 出错是否继续（continueOnError）
 */
import { ref } from 'vue';

import { message } from '#/adapter/naive';

export interface BatchExecOptions<T> {
  /** 单条任务执行函数 */
  task: (item: T, index: number) => Promise<any>;
  /** 并发数，默认 4 */
  concurrency?: number;
  /** 出错是否继续，默认 true */
  continueOnError?: boolean;
  /** 进度回调 */
  onProgress?: (done: number, total: number) => void;
  /** 用于错误信息中标识每一项的展示名 */
  identify?: (item: T, index: number) => string;
}

export interface BatchExecResult<T> {
  total: number;
  success: number;
  failed: number;
  errors: Array<{ item: T; index: number; error: any; identifier: string }>;
}

export function useBatchOps<T = any>() {
  const running = ref(false);
  const progress = ref(0);
  const total = ref(0);

  async function execute(
    items: T[],
    options: BatchExecOptions<T>,
  ): Promise<BatchExecResult<T>> {
    const concurrency = Math.max(1, options.concurrency ?? 4);
    const continueOnError = options.continueOnError ?? true;
    const identify = options.identify ?? ((_, i) => `#${i + 1}`);

    running.value = true;
    progress.value = 0;
    total.value = items.length;

    const result: BatchExecResult<T> = {
      total: items.length,
      success: 0,
      failed: 0,
      errors: [],
    };

    let cursor = 0;
    let aborted = false;

    async function worker() {
      while (!aborted) {
        const i = cursor++;
        if (i >= items.length) return;
        const item = items[i] as T;
        try {
          await options.task(item, i);
          result.success += 1;
        } catch (error: any) {
          result.failed += 1;
          result.errors.push({
            item,
            index: i,
            error,
            identifier: identify(item, i),
          });
          if (!continueOnError) {
            aborted = true;
          }
        } finally {
          progress.value += 1;
          options.onProgress?.(progress.value, items.length);
        }
      }
    }

    try {
      const workers: Promise<void>[] = [];
      for (let i = 0; i < Math.min(concurrency, items.length); i += 1) {
        workers.push(worker());
      }
      await Promise.all(workers);
    } finally {
      running.value = false;
    }

    return result;
  }

  /** 默认弹出聚合结果消息 */
  function notifyResult(action: string, result: BatchExecResult<T>) {
    if (result.failed === 0) {
      message.success(`${action}成功，共 ${result.success} 项`);
    } else if (result.success === 0) {
      message.error(
        `${action}失败 ${result.failed} 项${
          result.errors[0]?.error?.message
            ? '，原因：' + result.errors[0].error.message
            : ''
        }`,
      );
    } else {
      message.warning(
        `${action}部分成功：成功 ${result.success} 项，失败 ${result.failed} 项`,
      );
    }
  }

  return {
    running,
    progress,
    total,
    execute,
    notifyResult,
  };
}
