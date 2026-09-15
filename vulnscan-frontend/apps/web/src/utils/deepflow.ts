import { formatTimestamp } from './ly';

export function formatDeepflowDate(isoDate?: string) {
  return isoDate ? formatTimestamp(isoDate) : '';
}

export function mapSeverityToDisplay(severity?: string) {
  const map: Record<string, string> = {
    low: '低',
    medium: '中',
    high: '高',
    critical: '极高',
  };
  return map[severity || ''] || severity || '-';
}

export function mapSeverityToTagType(severity?: string) {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  if (severity === 'low') return 'success';
  return 'default';
}

export function getRoleName(from?: string) {
  const roleNameMap: Record<string, string> = {
    _operator: '安全工程师',
    _executor: '执行器',
    _manager: '安全管理员',
    _captain: '安全指挥官',
    _expert: '安全专家',
    ai_assistant: 'AI助手',
    system: '系统',
    user: '用户',
  };
  return roleNameMap[from || ''] || from || '系统';
}

export function normalizeDeepflowMessage(message: Record<string, any>, eventId = '') {
  const content = normalizeMessageContent(message.message_content || message.content);
  const createdAt =
    message.created_at ||
    message.updated_at ||
    message.timestamp ||
    content?.timestamp ||
    content?.data?.timestamp ||
    new Date().toISOString();

  return {
    ...message,
    created_at: createdAt,
    event_id: message.event_id || eventId,
    message_content: content,
    message_from: message.message_from || message.from || 'system',
    message_id: message.message_id || message.id || null,
    pending: Boolean(message.pending),
    temp_id: message.temp_id || null,
  };
}

export function normalizeMessageContent(raw: any): Record<string, any> {
  if (raw == null) return {};
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      return typeof parsed === 'object' && parsed ? normalizeMessageContent(parsed) : { text: raw };
    } catch {
      return { text: raw };
    }
  }
  if (typeof raw === 'object') {
    const normalized = Array.isArray(raw) ? [...raw] : { ...raw };
    Object.keys(normalized).forEach((key) => {
      const value = normalized[key];
      if (typeof value === 'string') {
        try {
          const parsed = JSON.parse(value);
          if (typeof parsed === 'object' && parsed !== null) {
            normalized[key] = normalizeMessageContent(parsed);
          }
        } catch {
          // Keep non-JSON strings as-is.
        }
      } else if (typeof value === 'object' && value !== null) {
        normalized[key] = normalizeMessageContent(value);
      }
    });
    return normalized;
  }
  return { text: String(raw) };
}

export function textFromAny(value: any): string {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function normalizeComparableText(value: any) {
  return textFromAny(value).replace(/\s+/g, '').trim();
}

function uniqueTextItems(items: any[], baseText = '') {
  const seen = new Set<string>();
  const base = normalizeComparableText(baseText);

  return items.filter((item) => {
    const normalized = normalizeComparableText(item);
    if (!normalized) return false;
    if (base && (normalized === base || base.includes(normalized) || normalized.includes(base))) {
      return false;
    }
    if (seen.has(normalized)) return false;
    seen.add(normalized);
    return true;
  });
}

export function getMessageDisplay(message: Record<string, any>) {
  const from = message?.message_from || '';
  const content = normalizeMessageContent(message?.message_content);
  const data = content?.data || {};
  const time =
    message?.updated_at ||
    message?.created_at ||
    content?.timestamp ||
    data?.timestamp ||
    '';

  function listItems(title: string, items: any[], mapper: (item: any, index: number) => string) {
    if (!items.length) return '';
    return `**${title}**\n\n${items.map(mapper).join('\n\n')}`;
  }

  // 不再使用表情图标，状态以文字形式展示
  function statusIcon(_status?: string) {
    return '';
  }

  function formatParams(params: any) {
    if (!params || typeof params !== 'object') return '';
    return Object.entries(params)
      .map(([key, value]) => `     - ${key}: ${textFromAny(value)}`)
      .join('\n');
  }

  const ctx =
    formatStructuredMessage(message, content, data) ||
    content?.content ||
    content?.text ||
    data?.response_text ||
    data?.text ||
    data?.decision ||
    data?.event_summary ||
    data?.ai_summary ||
    message?.message ||
    '';

  const isAi = message?.sender_type === 'ai' || from === 'ai_assistant';

  return {
    ctx: textFromAny(ctx),
    from: isAi ? getRoleName('ai_assistant') : getRoleName(from),
    isAi,
    time,
  };

  function formatStructuredMessage(
    source: Record<string, any>,
    sourceContent: Record<string, any>,
    sourceData: Record<string, any>,
  ) {
    const messageType = source?.message_type || '';

    if (messageType === 'task_created' || Array.isArray(sourceData?.tasks)) {
      const response = sourceData?.response_text
        ? `**指挥官研判**\n\n${sourceData.response_text}`
        : '';
      const tasks = listItems('已下发任务', sourceData?.tasks || [], (task, index) => {
        return `${index + 1}. ${statusIcon(task.task_status)} ${task.task_name || '-'}\n   - 类型: ${task.task_type || '-'}\n   - 指派: ${getRoleName(task.task_assignee || task.assigned_to)}\n   - 优先级: ${task.task_priority || '-'}\n   - 状态: ${task.task_status || '-'}${task.task_description ? `\n   - 说明: ${task.task_description}` : ''}`;
      });
      return [response, tasks].filter(Boolean).join('\n\n');
    }

    if (messageType === 'action_created' || Array.isArray(sourceData?.actions)) {
      const response = sourceData?.response_text
        ? `**安全管理员拆解**\n\n${sourceData.response_text}`
        : '';
      const actions = listItems('已创建动作', sourceData?.actions || [], (action, index) => {
        return `${index + 1}. ${statusIcon(action.action_status)} ${action.action_name || '-'}\n   - 类型: ${action.action_type || '-'}\n   - 执行者: ${getRoleName(action.action_assignee)}\n   - 状态: ${action.action_status || '-'}`;
      });
      return [response, actions].filter(Boolean).join('\n\n');
    }

    if (messageType === 'command_created' || Array.isArray(sourceData?.commands)) {
      const response = sourceData?.response_text
        ? `**操作员命令生成**\n\n${sourceData.response_text}`
        : '';
      const commands = listItems('已准备命令', sourceData?.commands || [], (command, index) => {
        const params = command.command_params?.data
          ? `\n   - 参数:\n${formatParams(command.command_params.data)}`
          : '';
        return `${index + 1}. ${statusIcon(command.command_status)} ${command.command_name || '-'}\n   - 类型: ${command.command_type || '-'}\n   - 执行者: ${getRoleName(command.command_assignee)}\n   - 状态: ${command.command_status || '-'}${params}`;
      });
      return [response, commands].filter(Boolean).join('\n\n');
    }

    if (messageType === 'command_result' || Array.isArray(sourceData?.executions)) {
      const response = sourceData?.response_text
        ? `**执行器反馈**\n\n${sourceData.response_text}`
        : '';
      const executions = listItems('执行结果', sourceData?.executions || [], (execution, index) => {
        const lines = [
          `${index + 1}. ${statusIcon(execution.execution_status)} ${execution.command_name || '-'}`,
          `   - 状态: ${execution.execution_status || '-'}`,
        ];
        if (execution.execution_summary) {
          lines.push(`   - 摘要: ${execution.execution_summary}`);
        }
        const result = execution.execution_result?.data;
        if (result) {
          if (result.verdict) lines.push(`   - 判定: ${result.verdict}`);
          if (result.summary) lines.push(`   - 结果: ${result.summary}`);
          if (Array.isArray(result.indicators) && result.indicators.length > 0) {
            lines.push(`   - 指标: ${result.indicators.join(', ')}`);
          }
        }
        const params = execution.command_params?.data;
        if (params) {
          lines.push(`   - 参数:\n${formatParams(params)}`);
        }
        return lines.join('\n');
      });
      return [response, executions].filter(Boolean).join('\n\n');
    }

    if (messageType === 'event_summary' || Array.isArray(sourceData?.summaries)) {
      const response = sourceData?.response_text
        ? `**专家复盘**\n\n${sourceData.response_text}`
        : '';
      const uniqueSummaries = Array.isArray(sourceData?.summaries)
        ? uniqueTextItems(sourceData.summaries, sourceData?.response_text)
        : [];
      const summaries = uniqueSummaries.length > 0
        ? `**事件总结**\n\n${uniqueSummaries.map((item: any) => `- ${textFromAny(item)}`).join('\n')}`
        : '';
      const uniqueSuggestions = Array.isArray(sourceData?.suggestions)
        ? uniqueTextItems(sourceData.suggestions, [sourceData?.response_text, ...uniqueSummaries].join('\n'))
        : [];
      const suggestions = uniqueSuggestions.length > 0
        ? `**建议**\n\n${uniqueSuggestions.map((item: any) => `- ${textFromAny(item)}`).join('\n')}`
        : '';
      return [response, summaries, suggestions].filter(Boolean).join('\n\n');
    }

    if (messageType === 'captain_llm_request' || sourceData?.type === 'llm_request') {
      // 仅展示面向用户的事件描述与观测指标；
      // 系统提示、可用剧本、组织背景等属于 LLM 内部输入，不应出现在对话中。
      return [
        sourceData?.request?.message ? `**事件描述**\n${sourceData.request.message}` : '',
        Array.isArray(sourceData?.request?.observables)
          ? `**观测指标**\n${sourceData.request.observables
              .map((item: any) => `- ${item.type}: ${item.value} (${item.role})`)
              .join('\n')}`
          : '',
      ]
        .filter(Boolean)
        .join('\n\n');
    }

    if (from === '_manager' && Array.isArray(sourceData?.actions)) {
      return `安排动作：${sourceData.actions.length}项`;
    }
    if (from === '_operator' && Array.isArray(sourceData?.commands)) {
      return `准备命令：${sourceData.commands.length}项`;
    }
    if (from === '_executor') {
      const statusText =
        sourceData?.status === 'completed'
          ? '已完成'
          : sourceData?.status === 'failed'
            ? '失败'
            : '执行中';
      const commandName =
        sourceData?.command_name || sourceData?.action_name || sourceData?.task_name || '任务';
      return `${commandName}${statusText}`;
    }

    if (sourceContent?.data && typeof sourceContent.data === 'object') return '';
    return '';
  }
}
