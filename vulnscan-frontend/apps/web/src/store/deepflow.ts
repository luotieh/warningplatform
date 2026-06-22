import { defineStore } from "pinia";

import { deepflowLogin } from "#/api/ly/deepflow";

const DEFAULT_CREDENTIALS = {
  username: "admin",
  password: "admin",
};

let loginPromise: null | Promise<string> = null;

export const useDeepflowStore = defineStore("deepflow", {
  state: () => ({
    accessToken: localStorage.getItem("deepflow_token") || "",
    userInfo: null as null | Record<string, any>,
  }),
  getters: {
    isLoggedIn: (state) => Boolean(state.accessToken),
  },
  actions: {
    setUser(user: null | Record<string, any>, token: string) {
      this.userInfo = user;
      this.accessToken = token;
      localStorage.setItem("deepflow_token", token);
      if (user) {
        localStorage.setItem("deepflow_userInfo", JSON.stringify(user));
      }
    },
    clearUser() {
      this.userInfo = null;
      this.accessToken = "";
      localStorage.removeItem("deepflow_token");
      localStorage.removeItem("deepflow_userInfo");
    },
    async ensureToken() {
      if (this.accessToken) return this.accessToken;
      if (loginPromise) return loginPromise;

      loginPromise = deepflowLogin(DEFAULT_CREDENTIALS)
        .then((res) => {
          console.log("[DeepFlow] 自动登录成功:", res);
          if (!res?.access_token) {
            throw new Error("DeepFlow 自动登录失败：未返回 access_token");
          }
          this.setUser(
            res.user ?? res.data ?? { username: DEFAULT_CREDENTIALS.username },
            res.access_token,
          );
          return res.access_token;
        })
        .finally(() => {
          loginPromise = null;
        });

      return loginPromise;
    },
    useToken(token: string, user: null | Record<string, any> = null) {
      this.setUser(user ?? { username: "auto_login" }, token);
      return token;
    },
  },
});
