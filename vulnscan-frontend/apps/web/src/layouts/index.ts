const BasicLayout = () => import('./basic.vue');
const AuthPageLayout = () => import('./auth.vue');
const EmbedLayout = () => import('./embed.vue');

const IFrameView = () => import('@vben/layouts').then((m) => m.IFrameView);

export { AuthPageLayout, BasicLayout, EmbedLayout, IFrameView };
