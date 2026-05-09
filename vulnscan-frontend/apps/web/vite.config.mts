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
        outDir: '../../../vulnscan-backend/frontend/dist',
        emptyOutDir: true,
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
