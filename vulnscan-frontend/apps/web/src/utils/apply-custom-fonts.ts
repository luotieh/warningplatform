import {
  CUSTOM_FONT_SOURCES,
  type CustomFontFile,
  type CustomFontSource,
} from '#/config/custom-fonts';

const STYLE_ID = 'vulnscan-custom-font-faces';

function guessFormat(url: string): CustomFontFile['format'] | undefined {
  const lower = url.toLowerCase();
  if (lower.endsWith('.woff2')) return 'woff2';
  if (lower.endsWith('.woff')) return 'woff';
  if (lower.endsWith('.ttf')) return 'truetype';
  if (lower.endsWith('.otf')) return 'opentype';
  return undefined;
}

function formatSrc(file: CustomFontFile): string {
  const format = file.format ?? guessFormat(file.url);
  const formatSuffix = format ? ` format('${format}')` : '';
  return `url('${file.url}')${formatSuffix}`;
}

function buildFaceRule(source: CustomFontSource, file: CustomFontFile): string {
  const weight = file.weight ?? 400;
  const style = file.style ?? 'normal';
  return `@font-face{font-family:'${source.family}';src:${formatSrc(file)};font-weight:${weight};font-style:${style};font-display:swap;}`;
}

export function registerCustomFontFaces(): void {
  if (typeof document === 'undefined' || CUSTOM_FONT_SOURCES.length === 0) {
    return;
  }
  const rules = CUSTOM_FONT_SOURCES.flatMap((source) =>
    source.files.map((file) => buildFaceRule(source, file)),
  );
  if (!rules.length) return;

  let el = document.getElementById(STYLE_ID) as HTMLStyleElement | null;
  if (!el) {
    el = document.createElement('style');
    el.id = STYLE_ID;
    document.head.appendChild(el);
  }
  el.textContent = rules.join('');
}
