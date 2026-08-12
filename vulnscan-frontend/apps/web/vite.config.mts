import { defineConfig } from '@vben/vite-config';

export default defineConfig(async () => {
  // mock/ 目录仅本地开发使用（已 gitignore）；不存在时跳过 mock 插件，
  // 避免克隆/CI 构建因缺少该目录而失败。
  const useEventMock = await import('node:fs')
    .then((fs) => fs.existsSync(new URL('./mock/event-mock.ts', import.meta.url)))
    .catch(() => false);
  const eventMockPlugin = useEventMock
    ? (await import('./mock/event-mock')).eventMockPlugin()
    : null;
  return {
    application: {
      devtools: false,
      print: false,
    },
    vite: {
      plugins: eventMockPlugin ? [eventMockPlugin] : [],
      build: {
        // ★ 直接输出到后端 embed 目录（见 vulnscan-backend/frontend/embed.go），单一二进制部署
        chunkSizeWarningLimit: 8000,
        outDir: '../../../vulnscan-backend/frontend/dist',
        emptyOutDir: true,
        rollupOptions: {
          onwarn(warning, warn) {
            if (
              warning.code === 'MODULE_LEVEL_DIRECTIVE'
              || (
                warning.message.includes('naive-ui')
                && warning.message.includes('dynamically imported by')
              )
            ) {
              return;
            }
            warn(warning);
          },
        },
      },
      optimizeDeps: {
        include: [
          'vue',
          'vue-router',
          'pinia',
          'naive-ui',
          'naive-ui/es/button',
          'naive-ui/es/checkbox',
          'naive-ui/es/date-picker',
          'naive-ui/es/divider',
          'naive-ui/es/input',
          'naive-ui/es/input-number',
          'naive-ui/es/radio',
          'naive-ui/es/select',
          'naive-ui/es/space',
          'naive-ui/es/switch',
          'naive-ui/es/time-picker',
          'naive-ui/es/tree-select',
          'naive-ui/es/upload',
          'axios',
          'monaco-editor',
        ],
      },
      server: {
        /** 固定 IPv4，避免用 localhost 打开页面时浏览器优先连 ::1 导致 TCP 建连多等 ~200–400ms */
        host: '127.0.0.1',
        proxy: {
          '/api': {
            changeOrigin: true,
            target: 'http://127.0.0.1:8090',
            ws: true,
          },
          '/callback': {
            changeOrigin: true,
            target: 'http://127.0.0.1:8090',
          },
          '/sso': {
            changeOrigin: true,
            target: 'http://127.0.0.1:8090',
          },
          '/health': {
            changeOrigin: true,
            target: 'http://127.0.0.1:8090',
          },
        },
      },
    },
  };
});
