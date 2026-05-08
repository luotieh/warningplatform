/**
 * IAM 请求客户端配置
 * 后端响应格式: { code: 2000, msg: "操作成功", data: {...}, count?: 0, timestamp: "..." }
 */
import type { RequestClientOptions } from '@vben/request';

import { LOGIN_PATH } from '@vben/constants';
import { useAppConfig } from '@vben/hooks';
import { preferences } from '@vben/preferences';
import {
  authenticateResponseInterceptor,
  defaultResponseInterceptor,
  errorMessageResponseInterceptor,
  RequestClient,
} from '@vben/request';
import { resetAllStores, useAccessStore } from '@vben/stores';

import { message } from '#/adapter/naive';

import { refreshTokenApi } from './core';

const { apiURL } = useAppConfig(import.meta.env, import.meta.env.PROD);

function createRequestClient(baseURL: string, options?: RequestClientOptions) {
  const client = new RequestClient({
    ...options,
    baseURL,
  });

  let isReAuthenticating = false;

  async function doReAuthenticate() {
    if (isReAuthenticating) return;
    isReAuthenticating = true;
    try {
      console.warn('Access token or refresh token is invalid or expired.');
      const accessStore = useAccessStore();
      accessStore.setAccessToken(null);
      if (
        preferences.app.loginExpiredMode === 'modal' &&
        accessStore.isAccessChecked
      ) {
        accessStore.setLoginExpired(true);
      } else {
        localStorage.removeItem('iam_refresh_token');
        localStorage.removeItem('iam_current_app_id');
        resetAllStores();
        if (!window.location.pathname.includes(LOGIN_PATH)) {
          const current = window.location.pathname + window.location.search;
          const redirect = current === '/' ? '' : `?redirect=${encodeURIComponent(current)}`;
          window.location.href = `${LOGIN_PATH}${redirect}`;
        }
      }
    } finally {
      isReAuthenticating = false;
    }
  }

  async function doRefreshToken() {
    const accessStore = useAccessStore();
    const resp = await refreshTokenApi();
    const newToken = resp.access_token;
    accessStore.setAccessToken(newToken);

    if (resp.refresh_token) {
      localStorage.setItem('iam_refresh_token', resp.refresh_token);
    }

    return newToken;
  }

  function formatToken(token: null | string) {
    return token ? `Bearer ${token}` : null;
  }

  client.addRequestInterceptor({
    fulfilled: async (config) => {
      const accessStore = useAccessStore();
      config.headers.Authorization = formatToken(accessStore.accessToken);
      config.headers['Accept-Language'] = preferences.app.locale;
      return config;
    },
  });

  // IAM 后端 code=2000 表示成功，data 字段承载业务数据
  client.addResponseInterceptor(
    defaultResponseInterceptor({
      codeField: 'code',
      dataField: 'data',
      successCode: 2000,
    }),
  );

  client.addResponseInterceptor(
    authenticateResponseInterceptor({
      client,
      doReAuthenticate,
      doRefreshToken,
      enableRefreshToken: preferences.app.enableRefreshToken,
      formatToken,
    }),
  );

  const AUTH_REVOKED_CODES = new Set([19301, 19302, 19303, 19304, 19401, 19402, 19403]);

  client.addResponseInterceptor({
    rejected: async (error: any) => {
      const code = error?.response?.data?.code;
      if (code && AUTH_REVOKED_CODES.has(code)) {
        await doReAuthenticate();
        return Promise.reject(
          Object.assign(new Error('auth_revoked'), { __silent: true }),
        );
      }
      return Promise.reject(error);
    },
  });

  const skipAuth = import.meta.env.VITE_SKIP_AUTH === 'true';

  client.addResponseInterceptor(
    errorMessageResponseInterceptor((msg: string, error) => {
      if (error?.__silent) return;
      if (error?.response?.status === 401) return;
      const responseData = error?.response?.data ?? {};
      const code = responseData?.code;
      if (code && AUTH_REVOKED_CODES.has(code)) return;
      if (skipAuth && error?.response?.status === 404) return;
      const errorMessage =
        responseData?.msg ?? responseData?.err ?? responseData?.message ?? '';
      message.error(errorMessage || msg);
    }),
  );

  return client;
}

export const requestClient = createRequestClient(apiURL, {
  responseReturn: 'data',
});

function createBaseRequestClient(baseURL: string) {
  const AUTH_REVOKED_CODES = new Set([19301, 19302, 19303, 19304, 19401, 19402, 19403]);

  const client = new RequestClient({ baseURL });
  client.addRequestInterceptor({
    fulfilled: async (config) => {
      const accessStore = useAccessStore();
      const token = accessStore.accessToken;
      config.headers.Authorization = token ? `Bearer ${token}` : null;
      config.headers['Accept-Language'] = preferences.app.locale;
      return config;
    },
  });
  client.addResponseInterceptor({
    fulfilled: async (response: any) => {
      const code = response?.data?.code;
      if (code && AUTH_REVOKED_CODES.has(code)) {
        localStorage.removeItem('iam_refresh_token');
        localStorage.removeItem('iam_current_app_id');
        resetAllStores();
        if (!window.location.pathname.includes(LOGIN_PATH)) {
          const current = window.location.pathname + window.location.search;
          const redirect = current === '/' ? '' : `?redirect=${encodeURIComponent(current)}`;
          window.location.href = `${LOGIN_PATH}${redirect}`;
        }
        return Promise.reject(
          Object.assign(new Error('auth_revoked'), { __silent: true }),
        );
      }
      return response;
    },
  });
  return client;
}

export const baseRequestClient = createBaseRequestClient(apiURL);
