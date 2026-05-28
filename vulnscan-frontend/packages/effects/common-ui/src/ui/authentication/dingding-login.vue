<script setup lang="ts">
import { SvgDingDingIcon } from '@vben/icons';
import { $t } from '@vben/locales';

import { alert, useVbenModal } from '@vben-core/popup-ui';
import { VbenIconButton } from '@vben-core/shadcn-ui';

interface Props {
  clientId: string;
  corpId: string;
  // 登录回调地址
  redirectUri?: string;
  // 是否内嵌二维码登录
  isQrCode?: boolean;
}

const props = defineProps<Props>();

const [Modal, modalApi] = useVbenModal({
  header: false,
  footer: false,
  fullscreenButton: false,
  class: 'w-[302px] h-[302px] dingding-qrcode-login-modal',
  onOpened() {
    handleQrCodeLogin();
  },
});

/**
 * 内嵌二维码登录
 */
const handleQrCodeLogin = async () => {
  await alert('钉钉登录依赖外部服务，当前系统已禁用前端外部网络请求。');
};

const handleLogin = () => {
  const { isQrCode } = props;
  if (isQrCode) {
    // 内嵌二维码登录
    modalApi.open();
  } else {
    alert('钉钉登录依赖外部服务，当前系统已禁用前端外部网络请求。');
  }
};
</script>

<template>
  <div>
    <VbenIconButton
      @click="handleLogin"
      :tooltip="$t('authentication.dingdingLogin')"
      tooltip-side="top"
    >
      <SvgDingDingIcon />
    </VbenIconButton>
    <Modal>
      <div id="dingding_qrcode_login_element"></div>
    </Modal>
  </div>
</template>

<style>
.dingding-qrcode-login-modal {
  .relative {
    padding: 0 !important;
  }
}
</style>
