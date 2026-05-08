import type { App } from 'vue';

import { registerPermDirective } from './perm';

export function registerCustomDirectives(app: App) {
  registerPermDirective(app);
}

export * from './perm';
