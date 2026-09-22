import DOMPurify from 'dompurify';
import { marked } from 'marked';

// marked 输出不做消毒，渲染前必须经 DOMPurify 过滤，防止 LLM 输出或
// 上游探针数据（事件名、域名、payload 文本）携带的 HTML/JS 进入 DOM。
export function sanitizeHtml(html: string): string {
  return DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
}

export function markdownToHtml(text?: string): string {
  if (!text) return '';
  try {
    return sanitizeHtml(marked.parse(text, { async: false }) as string);
  } catch {
    return sanitizeHtml(text);
  }
}
