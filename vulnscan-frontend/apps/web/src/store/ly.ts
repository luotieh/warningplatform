import { defineStore } from 'pinia';

import {
  lyBlacklistApi,
  lyDeviceApi,
  lyEventActionApi,
  lyEventGet,
  lyEventIgnoreApi,
  lyEventLevelApi,
  lyEventRulesApi,
  lyEventTypeApi,
  lyFeatureMo,
  lyInternalApi,
  lyLocalConfigList,
  lyMoApi,
  lyMoGroupApi,
  lyProxyApi,
  lyUserApi,
  lyWhitelistApi,
} from '#/api/ly';
import { normalizeLyEvents } from '#/utils/ly';

export const useLyStore = defineStore('ly', {
  state: () => ({
    loading: false,
    events: [] as Record<string, any>[],
    internal: [] as Record<string, any>[],
    black: [] as Record<string, any>[],
    white: [] as Record<string, any>[],
    device: [] as Record<string, any>[],
    proxy: [] as Record<string, any>[],
    userList: [] as Record<string, any>[],
    mo: [] as Record<string, any>[],
    moGroup: [] as Record<string, any>[],
    eventRules: [] as Record<string, any>[],
    eventIgnore: [] as Record<string, any>[],
    eventType: [] as Record<string, any>[],
    eventLevel: [] as Record<string, any>[],
    eventAction: [] as Record<string, any>[],
    moFeature: [] as Record<string, any>[],
  }),
  actions: {
    async loadEvents(params?: Record<string, any>) {
      this.loading = true;
      try {
        const data = await lyEventGet(params);
        this.events = normalizeLyEvents(Array.isArray(data) ? data : []);
        return this.events;
      } catch (error) {
        console.error('[ly] 加载事件列表失败', error);
        this.events = [];
        return this.events;
      } finally {
        this.loading = false;
      }
    },
    async loadConfigs() {
      const [
        internal,
        black,
        white,
        device,
        proxy,
        userList,
        mo,
        moGroup,
        eventRules,
        eventIgnore,
        eventType,
        eventLevel,
        eventAction,
      ] = await Promise.all([
        fallbackArray(lyInternalApi(), 'internalip'),
        fallbackArray(lyBlacklistApi(), 'blacklist'),
        fallbackArray(lyWhitelistApi(), 'whitelist'),
        fallbackArray(lyDeviceApi(), 'device'),
        fallbackArray(lyProxyApi(), 'proxy'),
        fallbackArray(lyUserApi(), 'user'),
        fallbackArray(lyMoApi(), 'mo'),
        fallbackArray(lyMoGroupApi(), 'mo_group'),
        fallbackArray(lyEventRulesApi(), 'event'),
        fallbackArray(lyEventIgnoreApi(), 'event_ignore'),
        fallbackArray(lyEventTypeApi(), 'event_type'),
        fallbackArray(lyEventLevelApi(), 'event_level'),
        fallbackArray(lyEventActionApi(), 'event_action'),
      ]);

      this.internal = internal;
      this.black = black;
      this.white = white;
      this.device = device;
      this.proxy = proxy;
      this.userList = userList;
      this.moGroup = moGroup;
      const groups = this.moGroup;
      this.mo = mo.map((item) => ({
        ...item,
        groupid:
          item.groupid ??
          item.mogroupid ??
          groups.find((group) => group.name === item.mogroup)?.id,
      }));
      this.eventRules = eventRules;
      this.eventIgnore = eventIgnore;
      this.eventType = eventType;
      this.eventLevel = eventLevel;
      this.eventAction = eventAction;
    },
    async loadTrackFeatures(params?: Record<string, any>) {
      const data = await fallbackArray(lyFeatureMo(params));
      this.moFeature = data;
      return this.moFeature;
    },
  },
});

async function fallbackArray<T extends Record<string, any>>(
  promise: Promise<T[]>,
  localCategory?: string,
) {
  try {
    const data = await promise;
    return mergeLocalItems(Array.isArray(data) ? data : [], localCategory);
  } catch (error) {
    console.error(`[ly] 加载配置失败${localCategory ? `（${localCategory}）` : ''}`, error);
    return mergeLocalItems([], localCategory);
  }
}

function mergeLocalItems<T extends Record<string, any>>(
  source: T[],
  localCategory?: string,
) {
  const local = localCategory ? lyLocalConfigList(localCategory) : [];
  if (!local.length) return source;

  const map = new Map<string, T | Record<string, any>>();
  source.forEach((item) => map.set(configItemKey(item), item));
  local.forEach((item) => {
    const key = configItemKey(item);
    if (item.__deleted) {
      map.delete(key);
      return;
    }
    map.set(key, item);
  });
  return Array.from(map.values()) as T[];
}

function configItemKey(item: Record<string, any>) {
  return String(
    item.__delete_key ??
      item.id ??
      item.config_id ??
      item.event_id ??
      item.group_id ??
      item.user_id ??
      item.value ??
      item.ip ??
      item.name ??
      item.moip ??
      '',
  );
}
