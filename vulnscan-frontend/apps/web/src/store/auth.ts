import type { Recordable, UserInfo } from '@vben/types';

import { ref } from 'vue';
import { useRouter } from 'vue-router';

import { LOGIN_PATH } from '@vben/constants';
import { preferences } from '@vben/preferences';
import { resetAllStores, useAccessStore, useUserStore } from '@vben/stores';

import { defineStore } from 'pinia';

import { notification } from '#/adapter/naive';
import { getAccessCodesApi, getUserInfoApi, loginApi, logoutApi } from '#/api';
import { changeExpiredPassword } from '#/api/core/public';
import { $t } from '#/locales';
import { isSSOMode, redirectToSSO } from '#/utils/sso';

export const useAuthStore = defineStore('auth', () => {
  const accessStore = useAccessStore();
  const userStore = useUserStore();
  const router = useRouter();

  const loginLoading = ref(false);
  const passwordExpired = ref(false);
  const expiredAccount = ref('');

  async function handleChangeExpiredPassword(
    account: string,
    oldPassword: string,
    newPassword: string,
  ) {
    await changeExpiredPassword({ account, old_password: oldPassword, new_password: newPassword });
    passwordExpired.value = false;
    expiredAccount.value = '';
  }

  async function authLogin(
    params: Recordable<any>,
    onSuccess?: () => Promise<void> | void,
  ) {
    let userInfo: null | UserInfo = null;
    try {
      loginLoading.value = true;

      let accessToken: string;
      let refreshToken: string | undefined;

      if (params.__webauthn_token) {
        accessToken = params.__webauthn_token;
        refreshToken = params.__webauthn_refresh;
      } else {
        const loginParams = {
          account: params.username || params.account,
          password: params.password,
          ...(params.captcha_key && { captcha_key: params.captcha_key }),
          ...(params.answer && { answer: params.answer }),
          ...(params.totp_code && { totp_code: params.totp_code }),
        };

        const loginResult = await loginApi(loginParams);

        if (loginResult.password_expired) {
          passwordExpired.value = true;
          expiredAccount.value = loginParams.account;
          loginLoading.value = false;
          return { userInfo: null, passwordExpired: true };
        }

        accessToken = loginResult.access_token;
        refreshToken = loginResult.refresh_token;
      }

      if (accessToken) {
        accessStore.setAccessToken(accessToken);

        if (refreshToken) {
          localStorage.setItem('iam_refresh_token', refreshToken);
        }

        const [fetchUserInfoResult, accessCodes] = await Promise.all([
          fetchUserInfo(),
          getAccessCodesApi(),
        ]);

        userInfo = fetchUserInfoResult;
        userStore.setUserInfo(userInfo);
        accessStore.setAccessCodes(accessCodes);

        if (accessStore.loginExpired) {
          accessStore.setLoginExpired(false);
        } else {
          onSuccess
            ? await onSuccess?.()
            : await router.push(
                userInfo.homePath || preferences.app.defaultHomePath,
              );
        }

        if (userInfo?.realName) {
          notification.success({
            content: $t('authentication.loginSuccess'),
            description: `${$t('authentication.loginSuccessDesc')}:${userInfo?.realName}`,
            duration: 3000,
          });
        }
      }
    } finally {
      loginLoading.value = false;
    }

    return {
      userInfo,
    };
  }

  const logoutInProgress = ref(false);

  async function logout(redirect: boolean = true) {
    if (logoutInProgress.value) return;
    logoutInProgress.value = true;
    try {
      await logoutApi();
    } catch {
      // ignore
    }
    localStorage.removeItem('iam_refresh_token');
    localStorage.removeItem('iam_current_app_id');
    resetAllStores();
    accessStore.setLoginExpired(false);

    if (isSSOMode()) {
      const next = redirect ? router.currentRoute.value.fullPath : '/';
      redirectToSSO(next);
    } else {
      await router.replace({
        path: LOGIN_PATH,
        query: redirect
          ? {
              redirect: encodeURIComponent(router.currentRoute.value.fullPath),
            }
          : {},
      });
    }
    logoutInProgress.value = false;
  }

  async function fetchUserInfo() {
    let userInfo: null | UserInfo = null;
    userInfo = await getUserInfoApi();
    userStore.setUserInfo(userInfo);
    return userInfo;
  }

  function $reset() {
    loginLoading.value = false;
  }

  return {
    $reset,
    authLogin,
    expiredAccount,
    fetchUserInfo,
    handleChangeExpiredPassword,
    loginLoading,
    logout,
    passwordExpired,
  };
});
