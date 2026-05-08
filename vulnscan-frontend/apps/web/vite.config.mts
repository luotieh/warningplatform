import { defineConfig } from '@vben/vite-config';

export default defineConfig(async () => {
  return {
    application: {
      devtools: false,
      print: false,
    },
    vite: {
      build: {
        // ★ 直接输出到后端 embed 目录，部署时一个二进制即可
        // 请根据实际后端目录名修改路径，如：'../../../my-biz-backend/frontend/dist'
        outDir: '../../../template-backend/frontend/dist',
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
