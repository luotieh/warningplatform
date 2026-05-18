import { defaultRegionCode } from '#/utils/region';

import { EXECUTOR_LOCAL_ID } from '../../scan/scan-executor';

import type {
  LedgerBatchEditField,
  LedgerBatchEditForm,
  LedgerConstructionForm,
  LedgerQuickOrganizeForm,
  LedgerFormModel,
  LedgerOption,
  LedgerScanForm,
  LedgerStats,
  LedgerUnitExtra,
  LedgerVerifyForm,
} from './types';

export const DEFAULT_ASSET_FAMILY_OPTIONS: LedgerOption[] = [
  { label: 'IP资产', value: 'ip' },
  { label: '域名网站', value: 'domain_site' },
  { label: '业务系统', value: 'business_system' },
  { label: '硬件设备', value: 'hardware' },
  { label: '软件资产', value: 'software' },
  { label: 'APP', value: 'app' },
  { label: '小程序', value: 'mini_program' },
  { label: '公众号', value: 'official_account' },
  { label: '公共邮箱', value: 'public_mailbox' },
  { label: '其他', value: 'other' },
];

export const DEFAULT_SOURCE_OPTIONS: LedgerOption[] = [
  { label: '手工录入', value: 'manual_import' },
  { label: '自动探测', value: 'auto_detect' },
  { label: '外部同步', value: 'external' },
  { label: '其他', value: 'other' },
];

export const DEFAULT_UNIT_TYPE_OPTIONS: LedgerOption[] = [
  { label: '政府机关', value: '政府机关' },
  { label: '事业单位', value: '事业单位' },
  { label: '国有企业', value: '国有企业' },
  { label: '企业', value: '企业' },
  { label: '私营企业', value: '私营企业' },
  { label: '其他', value: '其他' },
];

export const DEFAULT_INDUSTRY_CATEGORY_OPTIONS: LedgerOption[] = [
  { label: '政务', value: '政务' },
  { label: '金融', value: '金融' },
  { label: '教育', value: '教育' },
  { label: '医疗', value: '医疗' },
  { label: '能源', value: '能源' },
  { label: '通信', value: '通信' },
  { label: '交通', value: '交通' },
  { label: '其他', value: '其他' },
];

export const EMPTY_LEDGER_STATS = (): LedgerStats => ({
  total: 0,
  active: 0,
  keyAssets: 0,
  riskHigh: 0,
  withVulns: 0,
});

export const EMPTY_LEDGER_EXTRA = (): LedgerUnitExtra => ({
  contact_name: '',
  contact_phone: '',
  contact_title: '',
  department_leader_name: '',
  department_leader_phone: '',
  department_leader_title: '',
  industry_category: '',
  is_notification_member: false,
  leader_name: '',
  leader_title: '',
  responsible_department_name: '',
  unified_social_credit_code: '',
  unit_address: '',
  unit_location_code: defaultRegionCode,
  unit_type: '',
});

export const EMPTY_LEDGER_FORM = (): LedgerFormModel => ({
  name: '',
  assetFamily: 'ip',
  organizeId: '',
  dataNumber: '',
  address: '',
  ipv4: '',
  ipv6: '',
  port: null,
  isOnline: true,
  isKey: false,
  responsibleUserName: '',
  dataSource: 'manual_import',
  securityProtectionLevel: '',
  filingCertNumber: '',
  icpFilingNumber: '',
  publicSecurityFiling: '',
  operationOrgId: '',
  remark: '',
  extra: EMPTY_LEDGER_EXTRA(),
});

export const EMPTY_QUICK_CONSTRUCTION_FORM = (): LedgerConstructionForm => ({
  address: '',
  charge_person: '',
  charge_phone: '',
  location: '',
  location_code: defaultRegionCode,
  name: '',
});

export const EMPTY_QUICK_ORGANIZE_FORM = (): LedgerQuickOrganizeForm => ({
  name: '',
  parentId: '',
  unifiedSocialCreditCode: '',
});

export const EMPTY_SCAN_FORM = (): LedgerScanForm => ({
  name: '',
  templateId: '',
  enginePreset: '',
  priority: 5,
  verificationLevel: 'both',
  executorNodeIds: [EXECUTOR_LOCAL_ID],
});

export const EMPTY_VERIFY_FORM = (): LedgerVerifyForm => ({
  targetOrganizeId: '',
  sourceType: 'manual',
  remark: '',
});

export const VERIFY_SOURCE_OPTIONS: LedgerOption[] = [
  { label: '手工录入', value: 'manual' },
  { label: '导入', value: 'import' },
  { label: '探测发现', value: 'discovery' },
  { label: '扫描发现', value: 'scan' },
];

export const FAMILY_TABS = [
  { label: '全部', value: 'all' },
  { label: 'IP资产', value: 'ip' },
  { label: '域名网站', value: 'domain_site' },
  { label: '业务系统', value: 'business_system' },
  { label: '硬件设备', value: 'hardware' },
  { label: '软件资产', value: 'software' },
] as const;

export const EMPTY_BATCH_EDIT_FORM = (): LedgerBatchEditForm => ({
  field: '',
  value: '',
});

export const BOOLEAN_FILTER_OPTIONS: LedgerOption[] = [
  { label: '全部', value: '' },
  { label: '是', value: 'true' },
  { label: '否', value: 'false' },
];

export const BATCH_EDIT_FIELD_OPTIONS: Array<{
  label: string;
  value: LedgerBatchEditField;
}> = [
  { label: '所属单位', value: 'organize_id' },
  { label: '数据来源', value: 'data_source' },
  { label: '等保等级', value: 'security_protection_level' },
  { label: '责任人', value: 'responsible_user_name' },
  { label: '重点资产', value: 'is_key' },
  { label: '是否联网', value: 'is_online' },
  { label: '备注', value: 'remark' },
];

/** 列表表格 `scroll-x`：与列宽之和大致一致，改列定义时请同步 */
export const LEDGER_TABLE_SCROLL_X = 1480;
