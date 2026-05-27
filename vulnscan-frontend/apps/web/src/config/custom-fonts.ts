/**
 * 自定义字体注册表
 *
 * 1. 将字体文件放到 `apps/web/public/fonts/`（构建后可通过 `/fonts/xxx.woff2` 访问）
 * 2. 在 CUSTOM_FONT_SOURCES 中声明 @font-face（family + files）
 * 3. 在 `.env` 设置 VITE_APP_FONT_FAMILY=字体名，或在 preferences.ts 的 theme.fontFamily 中写完整 font-family 栈
 */

export interface CustomFontFile {
  url: string;
  weight?: number | string;
  style?: 'normal' | 'italic';
  format?: 'woff2' | 'woff' | 'truetype' | 'opentype';
}

export interface CustomFontSource {
  family: string;
  files: CustomFontFile[];
  fallback?: string;
}

export const DEFAULT_FONT_FALLBACK = `-apple-system, blinkmacsystemfont, 'Segoe UI', roboto, 'Helvetica Neue', arial, 'Noto Sans', sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji'`;

/**
 * 在此注册项目字体。示例（取消注释并放入对应文件后即可启用）：
 *
 * {
 *   family: 'Source Han Sans SC',
 *   files: [
 *     { url: '/fonts/SourceHanSansSC-Regular.woff2', weight: 400, format: 'woff2' },
 *     { url: '/fonts/SourceHanSansSC-Bold.woff2', weight: 700, format: 'woff2' },
 *   ],
 * },
 */
export const CUSTOM_FONT_SOURCES: CustomFontSource[] = [];

export function buildFontFamilyStack(
  family: string,
  fallback = DEFAULT_FONT_FALLBACK,
): string {
  const trimmed = family.trim();
  if (!trimmed) return fallback;
  const quoted = trimmed.includes(',') ? trimmed : `'${trimmed}'`;
  return `${quoted}, ${fallback}`;
}

export function resolveFontFamilyStack(
  familyName: string,
): string | undefined {
  const key = familyName.trim();
  if (!key) return undefined;
  const source = CUSTOM_FONT_SOURCES.find((s) => s.family === key);
  if (source) {
    return buildFontFamilyStack(
      source.family,
      source.fallback ?? DEFAULT_FONT_FALLBACK,
    );
  }
  return buildFontFamilyStack(key);
}
