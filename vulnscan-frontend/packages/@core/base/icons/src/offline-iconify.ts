import type { IconifyJSON } from '@iconify/types';

import { addCollection } from '@iconify/vue/offline';

import epIcons from '@iconify/json/json/ep.json';
import fluentMdl2Icons from '@iconify/json/json/fluent-mdl2.json';
import lucideIcons from '@iconify/json/json/lucide.json';
import mdiIcons from '@iconify/json/json/mdi.json';
import riIcons from '@iconify/json/json/ri.json';

const offlineCollections = [
  epIcons,
  fluentMdl2Icons,
  lucideIcons,
  mdiIcons,
  riIcons,
] as IconifyJSON[];
const collectionsByPrefix = new Map(
  offlineCollections.map((collection) => [collection.prefix, collection]),
);

let initialized = false;

export function registerOfflineIconifyCollections() {
  if (initialized) return;
  initialized = true;

  for (const collection of offlineCollections) {
    addCollection(collection);
  }
}

export function getOfflineIconNames(prefix: string) {
  registerOfflineIconifyCollections();
  const collection = collectionsByPrefix.get(prefix);
  if (!collection) return [];

  const names = new Set([
    ...Object.keys(collection.icons || {}),
    ...Object.keys(collection.aliases || {}),
  ]);

  return [...names].sort().map((name) => `${prefix}:${name}`);
}

registerOfflineIconifyCollections();
