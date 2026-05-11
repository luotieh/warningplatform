<script lang="ts" setup>
import { computed } from 'vue';

import { AuthPageLayout } from '@vben/layouts';
import { preferences } from '@vben/preferences';

import sloganImage from '#/assets/images/auth-scan-surface.svg';

const appName = computed(() => preferences.app.name);
const logo = computed(() => preferences.logo.source);
const logoDark = computed(() => preferences.logo.sourceDark);
</script>

<template>
  <AuthPageLayout
    :app-name="appName"
    :logo="logo"
    :logo-dark="logoDark"
    class="vuln-auth-page"
    page-description="以统一身份进入资产发现、漏洞扫描与风险处置流程"
    page-title="漏洞扫描与资产风险管理"
    :slogan-image="sloganImage"
  />
</template>

<style>
.vuln-auth-page {
  min-height: 100%;
  background:
    linear-gradient(135deg, rgba(240, 249, 255, 0.96), rgba(248, 250, 252, 0.98)),
    #f8fafc;
}

.vuln-auth-page .login-background {
  background:
    linear-gradient(135deg, rgba(14, 165, 233, 0.14), transparent 42%),
    linear-gradient(235deg, rgba(34, 197, 94, 0.1), transparent 44%),
    repeating-linear-gradient(
      90deg,
      rgba(3, 105, 161, 0.05) 0,
      rgba(3, 105, 161, 0.05) 1px,
      transparent 1px,
      transparent 54px
    ),
    repeating-linear-gradient(
      0deg,
      rgba(15, 23, 42, 0.035) 0,
      rgba(15, 23, 42, 0.035) 1px,
      transparent 1px,
      transparent 54px
    ) !important;
  filter: none !important;
}

.vuln-auth-page [data-side='left'],
.vuln-auth-page [data-side='right'] {
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.92), rgba(248, 250, 252, 0.96)),
    #fff;
  border-color: rgba(148, 163, 184, 0.18);
}

.vuln-auth-page [data-side='bottom'] {
  background: rgba(255, 255, 255, 0.9);
  border: 1px solid rgba(148, 163, 184, 0.18);
  border-radius: 16px !important;
  box-shadow: 0 24px 70px rgba(15, 23, 42, 0.11);
  backdrop-filter: blur(18px);
}

.vuln-auth-page .animate-float {
  width: min(46%, 520px);
  height: auto;
  max-height: 360px;
  animation: vuln-auth-float 7s ease-in-out infinite;
}

.vuln-auth-page .text-1xl,
.vuln-auth-page .lg\:text-2xl {
  font-weight: 700;
  line-height: 1.2;
  color: #0f172a;
  letter-spacing: 0;
}

.vuln-auth-page .dark\:text-muted-foreground {
  max-width: 520px;
  font-size: 15px;
  line-height: 1.8;
  color: #475569;
  text-align: center;
}

.dark .vuln-auth-page {
  background:
    linear-gradient(135deg, rgba(2, 6, 23, 0.98), rgba(8, 13, 28, 0.98)),
    #020617;
}

.dark .vuln-auth-page .login-background {
  background:
    linear-gradient(135deg, rgba(14, 165, 233, 0.12), transparent 46%),
    linear-gradient(230deg, rgba(34, 197, 94, 0.08), transparent 48%),
    repeating-linear-gradient(
      90deg,
      rgba(148, 163, 184, 0.08) 0,
      rgba(148, 163, 184, 0.08) 1px,
      transparent 1px,
      transparent 56px
    ),
    repeating-linear-gradient(
      0deg,
      rgba(148, 163, 184, 0.055) 0,
      rgba(148, 163, 184, 0.055) 1px,
      transparent 1px,
      transparent 56px
    ) !important;
}

.dark .vuln-auth-page [data-side='left'],
.dark .vuln-auth-page [data-side='right'],
.dark .vuln-auth-page [data-side='bottom'] {
  background:
    linear-gradient(180deg, rgba(15, 23, 42, 0.94), rgba(2, 6, 23, 0.96)),
    #020617;
  border-color: rgba(148, 163, 184, 0.16);
  box-shadow: 0 24px 70px rgba(0, 0, 0, 0.34);
}

.dark .vuln-auth-page .text-1xl,
.dark .vuln-auth-page .lg\:text-2xl {
  color: #f8fafc;
}

.dark .vuln-auth-page .dark\:text-muted-foreground {
  color: #cbd5e1;
}

@media (max-width: 1023px) {
  .vuln-auth-page [data-side='bottom'] {
    width: min(92vw, 480px) !important;
    padding-right: 20px;
    padding-left: 20px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .vuln-auth-page .animate-float {
    animation: none;
  }
}

@keyframes vuln-auth-float {
  0%,
  100% {
    transform: translateY(0);
  }

  50% {
    transform: translateY(-10px);
  }
}
</style>
