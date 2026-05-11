import { defineConfig } from '@vben/vite-config';

export default defineConfig(async () => {
  return {
    application: {
      devtools: false,
      print: false,
    },
    vite: {
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
        ],
      },
      server: {
        host: false,
        proxy: {
          '/api': {
            changeOrigin: true,
            target: 'http://127.0.0.1:8090',
            ws: true,
          },
        },
      },
    },
  };
});
