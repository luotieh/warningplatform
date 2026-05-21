<script lang="ts" setup>
import { computed } from 'vue';

import { AuthPageLayout } from '@vben/layouts';
import { preferences, usePreferences } from '@vben/preferences';

import sloganImage from '#/assets/images/auth-scan-surface.svg';

const { isDark } = usePreferences();

const appName = computed(
  () => import.meta.env.VITE_APP_TITLE || preferences.app.name,
);
const logo = computed(() => preferences.logo.source);
const logoDark = computed(() => preferences.logo.sourceDark);
const logoSrc = computed(() => {
  if (isDark.value && logoDark.value) {
    return logoDark.value;
  }
  return logo.value;
});

const brandFeatures = [
  { label: '风险监测', desc: '站点监测与漏洞发现' },
  { label: '通报处置', desc: '事件流转与闭环跟踪' },
  { label: '安全运营', desc: '资产台账与态势总览' },
] as const;
</script>

<template>
  <AuthPageLayout
    :app-name="''"
    :logo="logo"
    :logo-dark="logoDark"
    class="vuln-auth-page"
    page-description=""
    page-title=""
    :slogan-image="sloganImage"
  >
    <template #logo>
      <div class="vuln-auth-header">
        <img
          v-if="logoSrc"
          :alt="appName"
          :src="logoSrc"
          class="vuln-auth-header__logo"
          width="36"
        />
        <span class="vuln-auth-header__name lg:hidden">{{ appName }}</span>
      </div>
    </template>

    <template #intro>
      <div class="vuln-auth-intro">
        <img
          :alt="appName"
          :src="sloganImage"
          class="vuln-auth-intro__visual animate-float"
        />
        <p class="vuln-auth-intro__eyebrow">Network Security Early Warning</p>
        <h1 class="vuln-auth-intro__title">{{ appName }}</h1>
        <p class="vuln-auth-intro__desc">
          统一身份认证接入，覆盖风险监测、通报处置与安全运营全流程
        </p>
        <ul class="vuln-auth-intro__features">
          <li v-for="item in brandFeatures" :key="item.label">
            <strong>{{ item.label }}</strong>
            <span>{{ item.desc }}</span>
          </li>
        </ul>
      </div>
    </template>
  </AuthPageLayout>
</template>

<style>
.vuln-auth-page {
  min-height: 100%;
  background:
    linear-gradient(135deg, rgba(240, 249, 255, 0.96), rgba(248, 250, 252, 0.98)),
    #f8fafc;
}

.vuln-auth-header {
  display: flex;
  gap: 10px;
  align-items: center;
  margin: 16px 0 0 16px;
}

.vuln-auth-header__logo {
  border-radius: 10px;
  box-shadow: 0 8px 24px rgba(3, 105, 161, 0.12);
}

.vuln-auth-header__name {
  font-size: 15px;
  font-weight: 600;
  color: #0f172a;
}

.vuln-auth-intro {
  display: flex;
  flex-direction: column;
  align-items: center;
  max-width: 520px;
  padding: 0 24px;
  text-align: center;
}

.vuln-auth-intro__visual {
  width: min(72%, 420px);
  height: auto;
  max-height: 300px;
  margin-bottom: 8px;
}

.vuln-auth-intro__eyebrow {
  margin: 0;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: #0369a1;
}

.vuln-auth-intro__title {
  margin: 10px 0 0;
  font-size: clamp(28px, 3.2vw, 36px);
  font-weight: 800;
  line-height: 1.15;
  color: #0f172a;
  letter-spacing: 0.02em;
}

.vuln-auth-intro__desc {
  margin: 14px 0 0;
  font-size: 15px;
  line-height: 1.75;
  color: #475569;
}

.vuln-auth-intro__features {
  display: grid;
  gap: 10px;
  width: 100%;
  padding: 0;
  margin: 28px 0 0;
  list-style: none;
}

.vuln-auth-intro__features li {
  display: grid;
  gap: 2px;
  padding: 12px 14px;
  text-align: left;
  background: rgba(255, 255, 255, 0.72);
  border: 1px solid rgba(3, 105, 161, 0.12);
  border-radius: 12px;
  box-shadow: 0 10px 28px rgba(15, 23, 42, 0.04);
}

.vuln-auth-intro__features strong {
  font-size: 14px;
  color: #0f172a;
}

.vuln-auth-intro__features span {
  font-size: 13px;
  line-height: 1.5;
  color: #64748b;
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

.vuln-auth-page .min-h-full.flex-1 > .flex-col-center {
  background: #fff;
}

.vuln-auth-page .side-content {
  max-width: 400px;
}

.dark .vuln-auth-page {
  background:
    linear-gradient(135deg, rgba(2, 6, 23, 0.98), rgba(8, 13, 28, 0.98)),
    #020617;
}

.dark .vuln-auth-header__name {
  color: #f8fafc;
}

.dark .vuln-auth-intro__eyebrow {
  color: #38bdf8;
}

.dark .vuln-auth-intro__title {
  color: #f8fafc;
}

.dark .vuln-auth-intro__desc {
  color: #cbd5e1;
}

.dark .vuln-auth-intro__features li {
  background: rgba(15, 23, 42, 0.55);
  border-color: rgba(148, 163, 184, 0.18);
}

.dark .vuln-auth-intro__features strong {
  color: #f8fafc;
}

.dark .vuln-auth-intro__features span {
  color: #94a3b8;
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

.dark .vuln-auth-page .min-h-full.flex-1 > .flex-col-center {
  background: hsl(var(--background-deep));
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

.vuln-auth-page .animate-float {
  animation: vuln-auth-float 7s ease-in-out infinite;
}
</style>
