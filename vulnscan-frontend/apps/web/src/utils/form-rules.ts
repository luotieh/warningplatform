import type { FormItemRule, FormRules } from 'naive-ui';

import {
  validateCNPhone,
  validateIPv4List,
  validatePort,
  validateUSCC,
} from './validators';

/** 可选字段：失焦时校验，空值通过 */
function optionalBlurRule(validate: (value: string) => string | null): FormItemRule {
  return {
    trigger: ['blur', 'input'],
    validator: (_rule, value: string | number | null | undefined) => {
      const err = validate(String(value ?? '').trim());
      if (err) return new Error(err);
    },
  };
}

export const ipv4FormRule = optionalBlurRule(validateIPv4List);

export const portFormRule: FormItemRule = {
  trigger: ['blur', 'change'],
  validator: (_rule, value: number | null | undefined) => {
    const err = validatePort(value);
    if (err) return new Error(err);
  },
};

export function phoneFormRule(label: string): FormItemRule {
  return optionalBlurRule((v) => validateCNPhone(v, label));
}

export const usccFormRule = optionalBlurRule(validateUSCC);

/** 资产登记主表单 */
export const ledgerAssetFormRules: FormRules = {
  ipv4: ipv4FormRule,
  port: portFormRule,
  'extra.unified_social_credit_code': usccFormRule,
  'extra.department_leader_phone': phoneFormRule('负责人电话'),
  'extra.contact_phone': phoneFormRule('联系人电话'),
};

/** 单位管理 */
export const organizeProfileFormRules: FormRules = {
  unified_social_credit_code: usccFormRule,
  department_leader_phone: phoneFormRule('负责人电话'),
  contact_phone: phoneFormRule('联系人电话'),
};

/** 快速新增单位 */
export const quickOrganizeFormRules: FormRules = {
  unifiedSocialCreditCode: usccFormRule,
};

/** 快速新增运维单位 */
export const quickConstructionFormRules: FormRules = {
  charge_phone: phoneFormRule('联系电话'),
};
