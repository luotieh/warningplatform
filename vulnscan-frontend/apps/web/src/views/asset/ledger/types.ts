import type { Asset } from '#/api/asset';
import type { ScanTemplate } from '#/api/template';

export type LedgerOption = {
  label: string;
  value: string;
};

export type LedgerBatchEditField =
  | 'data_source'
  | 'is_key'
  | 'is_online'
  | 'organize_id'
  | 'remark'
  | 'responsible_user_name'
  | 'security_protection_level';

export type LedgerStats = {
  total: number;
  active: number;
  keyAssets: number;
  riskHigh: number;
  withVulns: number;
};

export type LedgerSearchForm = {
  keyword: string;
  assetFamily?: string;
  securityLevel?: string;
  dataSource?: string;
  riskScoreMin?: number | null;
  riskScoreMax?: number | null;
  isKey?: string;
};

export type LedgerUnitExtra = {
  contact_name: string;
  contact_phone: string;
  contact_title: string;
  department_leader_name: string;
  department_leader_phone: string;
  department_leader_title: string;
  industry_category: string;
  is_notification_member: boolean;
  leader_name: string;
  leader_title: string;
  responsible_department_name: string;
  unified_social_credit_code: string;
  unit_address: string;
  unit_location_code: string | null;
  unit_type: string;
};

export type LedgerFormModel = {
  name: string;
  assetFamily: string;
  organizeId: string;
  dataNumber: string;
  address: string;
  ipv4: string;
  ipv6: string;
  port: number | null;
  isOnline: boolean;
  isKey: boolean;
  responsibleUserName: string;
  dataSource: string;
  securityProtectionLevel: string;
  filingCertNumber: string;
  icpFilingNumber: string;
  publicSecurityFiling: string;
  operationOrgId: string;
  remark: string;
  extra: LedgerUnitExtra;
};

export type LedgerTableRow = Asset;

export type LedgerScanForm = {
  name: string;
  templateId: string;
  enginePreset: string;
  priority: number;
  verificationLevel: string;
  executorNodeIds: string[];
};

export type LedgerVerifyForm = {
  targetOrganizeId: string;
  sourceType: string;
  remark: string;
};

export type LedgerBatchEditForm = {
  field: '' | LedgerBatchEditField;
  value: boolean | number | string | null;
};

export type LedgerConstructionForm = {
  address: string;
  charge_person: string;
  charge_phone: string;
  location: string;
  location_code: null | string;
  name: string;
};

export type LedgerQuickOrganizeForm = {
  name: string;
  parentId: string;
  unifiedSocialCreditCode: string;
};

export type LedgerScanTemplate = ScanTemplate;
