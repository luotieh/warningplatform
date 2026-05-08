/**
 * 在 template 中渲染由 cell-renderers / 业务函数返回的 VNode。
 *
 * 用法：
 *   <RenderVNode :vnode="renderEnum(row.status, USER_STATUS)" />
 *   <RenderVNode :render="() => renderUserCell({ title, subtitle })" />
 */
import { defineComponent, type VNode } from 'vue';

export const RenderVNode = defineComponent({
  name: 'RenderVNode',
  props: {
    vnode: {
      type: [Object, Array, String, Number, null] as any,
      default: null,
    },
    render: {
      type: Function,
      default: null,
    },
  },
  setup(props) {
    return () => {
      if (typeof props.render === 'function') {
        return props.render();
      }
      return props.vnode as VNode;
    };
  },
});

export default RenderVNode;
