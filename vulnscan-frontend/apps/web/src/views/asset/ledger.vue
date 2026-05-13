<script lang="ts" setup>
import { computed, h, onMounted, reactive, ref } from 'vue';
import type { TreeOption } from 'naive-ui';
import {
  NButton, NCard, NCascader, NDataTable,
  NEmpty, NForm, NFormItem, NGrid, NGridItem, NInput, NInputNumber, NModal, NPopconfirm,
  NSelect, NSpace, NSwitch, NTag, NTree, NTooltip, NUpload, NDropdown, useMessage,
} from 'naive-ui';
import {
  Plus, Download, Upload, Edit, Scan, Trash2, MoreHorizontal,
  Server, Globe, ShieldAlert, Activity, CheckCircle2, AlertTriangle, Search,
  Pencil, FileText,
} from 'lucide-vue-next';
import type { UploadFileInfo } from 'naive-ui';
import { NStatistic } from 'naive-ui';
import { useRouter } from 'vue-router';
import type { Asset } from '#/api/asset';
import {
  createAsset,
  deleteAsset,
  getAssetList,
  getAssetStats,
  importAssets,
  updateAsset,
} from '#/api/asset';
import type { ConstructionOrg, Organize } from '#/api/assetmgr';
import { createConstruction, createVerifyTasks, getConstructionList, getOrganizeList, getOrganizeTree } from '#/api/assetmgr';
import type { DynamicFormSubmissionDetail, DynamicFormTemplate } from '#/api/formdesign';
import {
  getDynamicFormSubmission,
  getDynamicFormSubmissions,
  getDynamicFormTemplates,
  normalizePagedResponse,
  saveDynamicFormSubmission,
} from '#/api/formdesign';
import { dictItemsToOptions, getSystemDictItems } from '#/api/system/dict';
import { createTask } from '#/api/task';
import { requestClient } from '#/api/request';
import { regionCodeFromLabel, regionLabelFromCode, regionOptions } from '#/utils/region';
import DynamicFormRenderer from '#/components/dynamic-form/DynamicFormRenderer.vue';

defineOptions({ name: 'AssetLedger' });

const router = useRouter();
const message = useMessage();
const loading = ref(false);
const data = ref<Asset[]>([]);
const organizeOptions = ref<{ label: string; value: string }[]>([]);
const constructionOptions = ref<{ label: string; value: string }[]>([]);
const constructionMap = ref<Record<string, ConstructionOrg>>({});
const showUnitExtraFields = ref(false);
const showQuickConstructionModal = ref(false);
const quickConstructionTarget = ref<'construction' | 'operation'>('construction');
const linkQuickConstructionToBoth = ref(false);
const checkedKeys = ref<string[]>([]);
const showModal = ref(false);
const showImport = ref(false);
const importLoading = ref(false);
const editingId = ref<null | string>(null);
const assetDynamicTemplate = ref<DynamicFormTemplate | null>(null);
const assetDynamicFormData = ref<Record<string, any>>({});
const assetDynamicSubmission = ref<DynamicFormSubmissionDetail | null>(null);
const assetDynamicLoading = ref(false);
const sendingToMonitor = ref(false);
const submittingToVerify = ref(false);
const monitorResultVisible = ref(false);
const monitorResult = ref<any>(null);
const showBatchEdit = ref(false);
const batchEditLoading = ref(false);
const batchEditForm = reactive({
  field: '' as string,
  value: '' as string,
});
const exportLoading = ref(false);

const batchOptions = computed(() => [
  {
    label: '批量扫描',
    key: 'batch-scan',
    icon: () => h(Scan, { size: 16 }),
    disabled: !checkedKeys.value.length,
  },
  {
    label: '发送监控',
    key: 'send-monitor',
    icon: () => h(Activity, { size: 16 }),
    disabled: !checkedKeys.value.length,
  },
  {
    label: '提交核验',
    key: 'submit-verify',
    icon: () => h(CheckCircle2, { size: 16 }),
    disabled: !checkedKeys.value.length,
  },
  {
    type: 'divider' as const,
    key: 'divider',
  },
  {
    label: '批量编辑',
    key: 'batch-edit',
    icon: () => h(Edit, { size: 16 }),
    disabled: !checkedKeys.value.length,
  },
  {
    label: '批量删除',
    key: 'batch-delete',
    icon: () => h(Trash2, { size: 16 }),
    disabled: !checkedKeys.value.length,
    props: {
      style: { color: '#d03050' },
    },
  },
]);

const handleBatchSelect = (key: string | number) => {
  switch (key) {
    case 'batch-scan':
      onBatchScan();
      break;
    case 'send-monitor':
      onSendToMonitor();
      break;
    case 'submit-verify':
      onSubmitToVerify();
      break;
    case 'batch-edit':
      openBatchEdit();
      break;
    case 'batch-delete':
      onBatchDelete();
      break;
  }
};

const assetDynamicRenderOptions = computed(() => {
  const raw =
    assetDynamicSubmission.value?.version?.options
    || assetDynamicTemplate.value?.options
    || {};
  const rawForm = raw?.form ?? {};
  const rawRow = raw?.row ?? {};

  return {
    ...raw,
    form: {
      ...rawForm,
      labelPlacement: 'left',
      labelWidth: rawForm.labelWidth ?? '120px',
    },
    row: {
      ...rawRow,
      gutter: rawRow.gutter ?? 16,
    },
  };
});

function blurActiveElement() {
  const activeElement = document.activeElement;
  if (activeElement instanceof HTMLElement) {
    activeElement.blur();
  }
}

function setOverlayVisible(target: { value: boolean }, visible: boolean) {
  blurActiveElement();
  target.value = visible;
}

function setAssetModalVisible(visible: boolean) {
  setOverlayVisible(showModal, visible);
}

function setImportVisible(visible: boolean) {
  setOverlayVisible(showImport, visible);
}

function setQuickConstructionVisible(visible: boolean) {
  setOverlayVisible(showQuickConstructionModal, visible);
}

function setBatchEditVisible(visible: boolean) {
  setOverlayVisible(showBatchEdit, visible);
}

function setMonitorResultVisible(visible: boolean) {
  setOverlayVisible(monitorResultVisible, visible);
}

const pagination = reactive({
  page: 1, pageSize: 20, itemCount: 0, showSizePicker: true, pageSizes: [10, 20, 50, 100],
  onChange: (p: number) => { pagination.page = p; fetchList(); },
  onUpdatePageSize: (ps: number) => { pagination.pageSize = ps; pagination.page = 1; fetchList(); },
});

const searchForm = reactive({
  keyword: '', data_number: '', system_type: undefined as string | undefined,
  security_protection_level: undefined as string | undefined,
  data_source: undefined as string | undefined,
  asset_family: undefined as string | undefined, region_code: undefined as string | undefined,
  risk_score_min: undefined as number | undefined, risk_score_max: undefined as number | undefined,
  is_key: undefined as string | undefined, organize_id: undefined as string | undefined,
});

const showAdvancedFilter = ref(false);

const orgTree = ref<TreeOption[]>([]);
const selectedOrgKey = ref<null | string>(null);
const treeLoading = ref(false);

const stats = ref({
  keyAssets: 0,
  online: 0,
  riskHigh: 0,
  total: 0,
  withVulns: 0,
});

const now = new Date();
const thirtyDaysLater = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

const expiringSslAssets = computed(() =>
  data.value.filter(item => {
    if (!item.ssl_expires_at) return false;
    const d = new Date(item.ssl_expires_at);
    return d <= thirtyDaysLater && d >= now;
  }).slice(0, 10),
);

const expiringDomainAssets = computed(() =>
  data.value.filter(item => {
    if (!item.domain_expires_at) return false;
    const d = new Date(item.domain_expires_at);
    return d <= thirtyDaysLater && d >= now;
  }).slice(0, 10),
);

const expiredSslAssets = computed(() =>
  data.value.filter(item => {
    if (!item.ssl_expires_at) return false;
    return new Date(item.ssl_expires_at) < now;
  }).slice(0, 10),
);

const expiredDomainAssets = computed(() =>
  data.value.filter(item => {
    if (!item.domain_expires_at) return false;
    return new Date(item.domain_expires_at) < now;
  }).slice(0, 10),
);

const activeFamilyView = ref<'all' | 'ip' | 'domain_site' | 'business_system' | 'hardware' | 'software'>('all');

const extraDefaults = {
  unit_type: '',
  industry_category: '',
  is_notification_member: false,
  unified_social_credit_code: '',
  unit_address: '',
  unit_detail_address: '',
  leader_name: '',
  leader_title: '',
  responsible_department_name: '',
  department_leader_name: '',
  department_leader_title: '',
  department_leader_phone: '',
  contact_name: '',
  contact_title: '',
  contact_phone: '',
};

type AssetExtra = typeof extraDefaults;

const formData = reactive({
  name: '', type: 'server', address: '', port: 0, domain: '', ipv4: '', ipv6: '', url: '', protocol: '',
  service: '', version: '', os: '', data_number: '', system_type: '',
  is_online: true, is_key: false, security_protection_level: '', filing_cert_number: '',
  icp_filing_number: '', public_security_filing: '', organize_id: '', construction_org_id: '', operation_org_id: '', data_source: 'manual_import',
  asset_family: 'ip', asset_subtype: '', region_code: '', region_name: '',
  responsible_user_name: '', remark: '', tags: [] as string[],
  extra: { ...extraDefaults } as AssetExtra,
});

const quickConstructionForm = reactive({
  name: '',
  location: '',
  location_code: null as null | string,
  address: '',
  charge_person: '',
  charge_phone: '',
  security_filing: '',
});


type DictOption = { label: string; value: string };

const defaultSystemTypeOptions: DictOption[] = [
  { label: '网站', value: 'url' }, { label: '应用系统', value: 'application' },
  { label: '数据库', value: 'database' }, { label: '服务器', value: 'server' },
  { label: '网络设备', value: 'network' }, { label: '安全设备', value: 'security' },
];
const defaultAssetTypeOptions: DictOption[] = [...defaultSystemTypeOptions];
const assetFamilyOptions: DictOption[] = [
  { label: 'IP资产', value: 'ip' },
  { label: '域名网站', value: 'domain_site' },
  { label: '业务系统', value: 'business_system' },
  { label: '硬件设备', value: 'hardware' },
  { label: '软件资产', value: 'software' },
  { label: 'APP', value: 'app' },
  { label: '小程序', value: 'mini_program' },
  { label: '公众号', value: 'official_account' },
  { label: '公共邮箱', value: 'public_mailbox' },
];
const assetSubtypeMap: Record<string, DictOption[]> = {
  app: [
    { label: 'Android APP', value: 'android_app' },
    { label: 'iOS APP', value: 'ios_app' },
    { label: '双端APP', value: 'multi_app' },
  ],
  business_system: [
    { label: '业务信息系统', value: 'business_info_system' },
    { label: '业务支撑系统', value: 'support_system' },
    { label: '门户网站', value: 'portal_site' },
  ],
  domain_site: [
    { label: '门户网站', value: 'portal_site' },
    { label: '业务网站', value: 'business_site' },
    { label: '域名', value: 'domain' },
  ],
  hardware: [
    { label: '服务器', value: 'server' },
    { label: '防火墙', value: 'firewall' },
    { label: 'VPN设备', value: 'vpn' },
    { label: 'WAF', value: 'waf' },
    { label: '交换机/路由器', value: 'network_device' },
  ],
  ip: [
    { label: 'IPv4', value: 'ipv4' },
    { label: 'IPv6', value: 'ipv6' },
    { label: '公网IP', value: 'public_ip' },
    { label: '内网IP', value: 'private_ip' },
  ],
  mini_program: [
    { label: '微信小程序', value: 'wechat_mini_program' },
    { label: '支付宝小程序', value: 'alipay_mini_program' },
  ],
  official_account: [
    { label: '服务号', value: 'service_account' },
    { label: '订阅号', value: 'subscription_account' },
  ],
  public_mailbox: [
    { label: '公共邮箱', value: 'public_mailbox' },
  ],
  software: [
    { label: '基础软件', value: 'base_software' },
    { label: '中间件', value: 'middleware' },
    { label: '应用软件', value: 'application_software' },
  ],
};
const defaultSecurityOptions: DictOption[] = [
  { label: '一级', value: 'level1' }, { label: '二级', value: 'level2' },
  { label: '三级', value: 'level3' }, { label: '四级', value: 'level4' }, { label: '五级', value: 'level5' },
];
const defaultSourceOptions: DictOption[] = [
  { label: '手动导入', value: 'manual_import' }, { label: '自动探测', value: 'auto_detect' },
  { label: '外部集成', value: 'external' },
];

const systemTypeOptions = ref<DictOption[]>([...defaultSystemTypeOptions]);
const assetTypeOptions = ref<DictOption[]>([...defaultAssetTypeOptions]);
const securityOptions = ref<DictOption[]>([...defaultSecurityOptions]);
const sourceOptions = ref<DictOption[]>([...defaultSourceOptions]);
const assetSubtypeOptions = computed<DictOption[]>(() => assetSubtypeMap[formData.asset_family] || []);
const showAddressFields = computed(() => ['business_system', 'domain_site', 'hardware', 'ip', 'software', 'app'].includes(formData.asset_family));
const showPortField = computed(() => ['business_system', 'domain_site', 'hardware', 'software'].includes(formData.asset_family));
const showConstructionFields = computed(() => ['business_system', 'domain_site', 'hardware', 'software', 'app', 'mini_program', 'official_account', 'public_mailbox'].includes(formData.asset_family));
const showResponsibleField = computed(() => formData.asset_family !== 'ip');
const showTypeField = computed(() => ['hardware', 'software', 'business_system', 'domain_site'].includes(formData.asset_family));

function onAssetFamilyChange(value: string) {
  formData.asset_family = value;
  formData.asset_subtype = '';
}

function changeFamilyView(view: 'all' | 'ip' | 'domain_site' | 'business_system' | 'hardware' | 'software') {
  activeFamilyView.value = view;
  searchForm.asset_family = view === 'all' ? undefined : view;
  pagination.page = 1;
  fetchList();
}

function familyViewButtonType(view: 'all' | 'ip' | 'domain_site' | 'business_system' | 'hardware' | 'software') {
  return activeFamilyView.value === view ? 'primary' : 'default';
}

function assetFamilyLabel(value?: string) {
  if (!value) return '-';
  return assetFamilyOptions.find(item => item.value === value)?.label || value;
}

function assetSubtypeLabel(family?: string, subtype?: string) {
  if (!subtype) return '-';
  return (assetSubtypeMap[family || ''] || []).find(item => item.value === subtype)?.label || subtype;
}

function assetPrimaryIdentifier(asset?: Partial<Asset> | null) {
  if (!asset) return '-';
  if (asset.asset_family === 'domain_site') {
    return asset.domain || asset.url || asset.address || '-';
  }
  if (asset.asset_family === 'ip') {
    return asset.ipv4 || asset.ipv6 || asset.address || '-';
  }
  if (asset.asset_family === 'public_mailbox') {
    return asset.address || asset.url || '-';
  }
  return asset.address || asset.domain || asset.url || '-';
}

function formatDateTime(value?: string) {
  if (!value) return '-';
  return value.replace('T', ' ').replace(/\.\d+.*$/, '');
}

const visibleColumns = computed(() => {
  const common = ['name', 'asset_family', 'organize_id', 'region_name', 'risk_score', 'vuln_count', 'responsible_user_name', 'created_at', 'actions'];
  const byView: Record<string, string[]> = {
    all: ['primary_identifier'],
    ip: ['primary_identifier'],
    domain_site: ['primary_identifier'],
    business_system: ['primary_identifier'],
    hardware: ['primary_identifier'],
    software: ['primary_identifier'],
  };
  const keys = new Set([...common, ...(byView[activeFamilyView.value] ?? byView.all ?? [])]);
  return columns.filter((column: any) => {
    if (column.type === 'selection') return true;
    return keys.has(column.key);
  });
});

const systemTypeMap = computed<Record<string, string>>(() => Object.fromEntries(systemTypeOptions.value.map(o => [o.value, o.label])));
const assetTypeMap = computed<Record<string, string>>(() => Object.fromEntries(assetTypeOptions.value.map(o => [o.value, o.label])));
const sourceMap = computed<Record<string, string>>(() => Object.fromEntries(sourceOptions.value.map(o => [o.value, o.label])));

function assetTypeLabel(value: unknown) {
  const key = String(value ?? '');
  return assetTypeMap.value[key] || key || '-';
}

function inferAssetFamily(asset: Partial<Asset>) {
  if (asset.asset_family) return asset.asset_family;
  if (asset.url || asset.domain) return 'domain_site';
  if (asset.type === 'network' || asset.type === 'security') return 'hardware';
  if (asset.system_type === 'application') return 'business_system';
  return 'ip';
}

function mergeExtra(extra?: Record<string, any> | null): AssetExtra {
  return { ...extraDefaults, ...(extra ?? {}) };
}


function organizeLabel(id?: string) {
  if (!id) return '-';
  return organizeOptions.value.find(item => item.value === id)?.label || id;
}


function normalizeListResponse<T>(res: any): T[] {
  const body = res?.data ?? res;
  return body?.data ?? body?.items ?? [];
}

function normalizeItemResponse<T>(res: any): T {
  const body = res?.data ?? res;
  return (body?.data ?? body) as T;
}

async function loadAssetDynamicTemplate(objectType?: string) {
  try {
    const res = await getDynamicFormTemplates({
      business: 'asset',
      enabled: 'true',
      object_type: objectType || undefined,
      page: 1,
      page_size: 20,
    });
    let items = normalizePagedResponse<DynamicFormTemplate>(res).items;
    if (!items.length && objectType) {
      const fallback = await getDynamicFormTemplates({
        business: 'asset',
        enabled: 'true',
        page: 1,
        page_size: 20,
      });
      items = normalizePagedResponse<DynamicFormTemplate>(fallback).items;
    }
    assetDynamicTemplate.value = items.find(item => item.is_default) || items[0] || null;
  } catch {
    assetDynamicTemplate.value = null;
  }
}

async function loadAssetDynamicSubmission(assetId: string) {
  assetDynamicSubmission.value = null;
  assetDynamicFormData.value = {};
  if (!assetDynamicTemplate.value) return;
  assetDynamicLoading.value = true;
  try {
    const res = await getDynamicFormSubmissions({
      business: 'asset',
      object_id: assetId,
      page: 1,
      page_size: 1,
      template_id: assetDynamicTemplate.value.id,
    });
    const item = normalizePagedResponse<any>(res).items[0];
    if (!item?.id) return;
    const detail = await getDynamicFormSubmission(item.id);
    assetDynamicSubmission.value = detail;
    assetDynamicFormData.value = { ...(detail.submission?.form_data || {}) };
  } catch {
    assetDynamicSubmission.value = null;
  } finally {
    assetDynamicLoading.value = false;
  }
}

async function saveAssetDynamicForm(assetId: string) {
  if (!assetDynamicTemplate.value) return;
  await saveDynamicFormSubmission({
    business: 'asset',
    form_data: assetDynamicFormData.value,
    object_id: assetId,
    object_type: formData.type || formData.system_type || 'asset',
    template_id: assetDynamicTemplate.value.id,
    template_version_id: assetDynamicSubmission.value?.submission?.template_version_id || assetDynamicTemplate.value.current_version_id,
  });
}

async function loadDictOptions() {
  const loaders: Array<[string, typeof systemTypeOptions, DictOption[]]> = [
    ['asset_system_type', systemTypeOptions, defaultSystemTypeOptions],
    ['asset_type', assetTypeOptions, defaultAssetTypeOptions],
    ['asset_security_level', securityOptions, defaultSecurityOptions],
    ['asset_data_source', sourceOptions, defaultSourceOptions],
  ];

  await Promise.all(loaders.map(async ([dictId, target, fallback]) => {
    try {
      const options = dictItemsToOptions(await getSystemDictItems(dictId, true));
      target.value = options.length > 0 ? options : [...fallback];
    } catch {
      target.value = [...fallback];
    }
  }));
}

async function loadReferenceOptions() {
  try {
    const res = await getOrganizeList({ page: 1, page_size: 500 });
    const body = (res as any)?.data ?? res;
    const items = (body?.data ?? body?.items ?? []) as Organize[];
    organizeOptions.value = items.map((item) => ({
      label: item.name,
      value: item.id,
    }));
  } catch {
    organizeOptions.value = [];
  }

  try {
    const items = normalizeListResponse<ConstructionOrg>(await getConstructionList({ page: 1, page_size: 100 }));
    constructionOptions.value = items.map(item => ({ label: item.name, value: item.id }));
    constructionMap.value = Object.fromEntries(items.map(item => [item.id, item]));
  } catch {
    constructionOptions.value = [];
    constructionMap.value = {};
  }
}

function resetQuickConstructionForm() {
  Object.assign(quickConstructionForm, {
    name: '',
    location: '',
    location_code: null,
    address: '',
    charge_person: '',
    charge_phone: '',
    security_filing: '',
  });
  linkQuickConstructionToBoth.value = quickConstructionTarget.value === 'construction';
}

function openQuickConstruction(target: 'construction' | 'operation') {
  quickConstructionTarget.value = target;
  resetQuickConstructionForm();
  setQuickConstructionVisible(true);
}

function useConstructionAsOperation() {
  if (!formData.construction_org_id) {
    message.warning('请先选择建设单位');
    return;
  }
  formData.operation_org_id = formData.construction_org_id;
}

function useOperationAsConstruction() {
  if (!formData.operation_org_id) {
    message.warning('请先选择运维单位');
    return;
  }
  formData.construction_org_id = formData.operation_org_id;
}

function applyConstructionSelection(id: string) {
  if (quickConstructionTarget.value === 'construction') {
    formData.construction_org_id = id;
    if (linkQuickConstructionToBoth.value) formData.operation_org_id = id;
    return;
  }
  formData.operation_org_id = id;
  if (linkQuickConstructionToBoth.value) formData.construction_org_id = id;
}

async function onQuickConstructionSave() {
  if (!quickConstructionForm.name) {
    message.warning('请输入单位名称');
    return;
  }
  try {
    const item = normalizeItemResponse<ConstructionOrg>(await createConstruction({
      name: quickConstructionForm.name,
      location: regionLabelFromCode(quickConstructionForm.location_code) || quickConstructionForm.location,
      address: quickConstructionForm.address,
      charge_person: quickConstructionForm.charge_person,
      charge_phone: quickConstructionForm.charge_phone,
      security_filing: quickConstructionForm.security_filing,
    }));
    await loadReferenceOptions();
    applyConstructionSelection(item.id);
    setQuickConstructionVisible(false);
    message.success('单位已新增并关联');
  } catch {
    message.error('新增单位失败');
  }
}

const columns = [
  { type: 'selection' as const, width: 50 },
  { title: '系统名称', key: 'name', width: 160, ellipsis: { tooltip: true },
    render: (row: Asset) => row.name || '-' },
  { title: '资产分类', key: 'asset_family', width: 100,
    render: (row: Asset) => assetFamilyLabel(row.asset_family) },
  { title: '访问地址', key: 'primary_identifier', width: 180, ellipsis: { tooltip: true },
    render: (row: Asset) => assetPrimaryIdentifier(row) },
  { title: '所属单位', key: 'organize_id', width: 140, ellipsis: { tooltip: true },
    render: (row: Asset) => organizeLabel(row.organize_id) },
  { title: '地域', key: 'region_name', width: 120, ellipsis: { tooltip: true },
    render: (row: Asset) => row.region_name || '-' },
  { title: '风险分', key: 'risk_score', width: 80,
    render: (row: Asset) => h('span', { style: { color: (row.risk_score ?? 0) >= 70 ? '#d03050' : (row.risk_score ?? 0) >= 40 ? '#f0a020' : '#18a058' } }, String(row.risk_score ?? 0)) },
  { title: '漏洞', key: 'vuln_count', width: 60,
    render: (row: Asset) => (row.vuln_count ?? 0) > 0
      ? h(NTag, { size: 'small', type: 'error', bordered: false }, () => String(row.vuln_count))
      : h('span', { style: 'color: #ccc' }, '0') },
  { title: '责任人', key: 'responsible_user_name', width: 100 },
  { title: '创建时间', key: 'created_at', width: 150,
    render: (row: Asset) => formatDateTime(row.created_at) },
  { title: '操作', key: 'actions', width: 160, fixed: 'right' as const,
    render: (row: Asset) => h(NSpace, { size: 2 }, () => [
      h(NPopconfirm, { onPositiveClick: () => onScan(row) }, {
        trigger: () => h(NTooltip, { trigger: 'hover' }, {
          trigger: () => h(NButton, { size: 'small', type: 'warning', quaternary: true }, {
            default: () => h(Scan, { size: 16 }),
          }),
          default: () => '扫描',
        }),
        default: () => `对 ${assetPrimaryIdentifier(row)} 发起漏洞扫描？`,
      }),
      h(NTooltip, { trigger: 'hover' }, {
        trigger: () => h(NButton, { size: 'small', type: 'info', quaternary: true, onClick: () => onDetail(row) }, {
          default: () => h(FileText, { size: 16 }),
        }),
        default: () => '详情',
      }),
      h(NTooltip, { trigger: 'hover' }, {
        trigger: () => h(NButton, { size: 'small', quaternary: true, onClick: () => onEdit(row) }, {
          default: () => h(Pencil, { size: 16 }),
        }),
        default: () => '编辑',
      }),
      h(NPopconfirm, { onPositiveClick: () => onDelete(row.id) }, {
        trigger: () => h(NTooltip, { trigger: 'hover' }, {
          trigger: () => h(NButton, { size: 'small', type: 'error', quaternary: true }, {
            default: () => h(Trash2, { size: 16 }),
          }),
          default: () => '删除',
        }),
        default: () => '确认删除？',
      }),
    ]),
  },
];

async function fetchList() {
  loading.value = true;
  try {
    const params: Record<string, any> = {
      page: pagination.page,
      page_size: pagination.pageSize,
      ...searchForm,
    };
    const res = await getAssetList(params);
    data.value = res.items ?? [];
    pagination.itemCount = res.total ?? 0;
  } catch { message.error('获取资产台账失败'); }
  finally { loading.value = false; }
  fetchStats();
}

async function fetchStats() {
  try {
    const params: Record<string, any> = {};
    if (searchForm.asset_family) {
      params.asset_family = searchForm.asset_family;
    }
    const res = await getAssetStats(params);
    const body = (res as any)?.data ?? res;
    Object.assign(stats.value, {
      keyAssets: body?.key_assets ?? 0,
      online: body?.active ?? 0,
      riskHigh: body?.risk_high ?? 0,
      total: body?.total ?? 0,
      withVulns: body?.with_vulns ?? 0,
    });
  } catch { /* 统计加载失败不影响主流程 */ }
}

function onSearch() { pagination.page = 1; fetchList(); }
function onReset() {
  activeFamilyView.value = 'all';
  showAdvancedFilter.value = false;
  Object.assign(searchForm, {
    keyword: '',
    data_number: '',
    system_type: undefined,
    security_protection_level: undefined,
    data_source: undefined,
    asset_family: undefined,
    region_code: undefined,
    risk_score_min: undefined,
    risk_score_max: undefined,
    is_key: undefined,
    organize_id: undefined,
  });
  onSearch();
}

function resetForm() {
  Object.assign(formData, {
    name: '', type: 'server', address: '', port: 0, domain: '', ipv4: '', ipv6: '', url: '', protocol: '',
    service: '', version: '', os: '', data_number: '', system_type: '',
    is_online: true, is_key: false, security_protection_level: '', filing_cert_number: '',
    icp_filing_number: '', public_security_filing: '', organize_id: '', construction_org_id: '', operation_org_id: '', data_source: 'manual_import',
    asset_family: 'ip', asset_subtype: '', region_code: '', region_name: '',
    responsible_user_name: '', remark: '', tags: [], extra: mergeExtra(),
  });
  showUnitExtraFields.value = false;
  assetDynamicFormData.value = {};
  assetDynamicSubmission.value = null;
}

async function onAdd() {
  editingId.value = null;
  resetForm();
  await loadAssetDynamicTemplate(formData.type || formData.system_type);
  setAssetModalVisible(true);
}

async function onEdit(row: Asset) {
  editingId.value = row.id;
  Object.assign(formData, {
    name: row.name, type: row.type, address: row.address, port: row.port ?? 0,
    domain: row.domain ?? '', ipv4: row.ipv4 ?? '', url: row.url ?? '', protocol: row.protocol ?? '',
    ipv6: row.ipv6 ?? '',
    service: row.service ?? '', version: row.version ?? '', os: row.os ?? '',
    data_number: row.data_number ?? '', system_type: row.system_type ?? '',
    is_online: row.is_online ?? true, is_key: row.is_key ?? false,
    security_protection_level: row.security_protection_level ?? '',
    filing_cert_number: row.filing_cert_number ?? '', icp_filing_number: row.icp_filing_number ?? '',
    public_security_filing: row.public_security_filing ?? '',
    organize_id: row.organize_id ?? '',
    construction_org_id: row.construction_org_id ?? '', operation_org_id: row.operation_org_id ?? '',
    data_source: row.data_source ?? 'manual_import',
    asset_family: row.asset_family ?? inferAssetFamily(row),
    asset_subtype: row.asset_subtype ?? '',
    region_code: row.region_code ?? regionCodeFromLabel(row.region_name) ?? '',
    region_name: row.region_name ?? '',
    responsible_user_name: row.responsible_user_name ?? '', remark: row.remark ?? '',
    tags: row.tags ?? [], extra: mergeExtra(row.extra),
  });
  showUnitExtraFields.value = Object.entries(row.extra ?? {}).some(([key, value]) => key in extraDefaults && value !== undefined && value !== null && value !== '');
  await loadAssetDynamicTemplate(row.type || row.system_type);
  await loadAssetDynamicSubmission(row.id);
  setAssetModalVisible(true);
}

function onDetail(row: Asset) {
  router.push(`/asset/detail/${row.id}`);
}

async function onSaveWithDynamicForm() {
  if (!formData.name) {
    message.warning('请填写系统名称');
    return;
  }
  if (!formData.system_type) {
    message.warning('请选择系统类型');
    return;
  }
  if (!formData.ipv4 && !formData.address) {
    message.warning('请填写IPV4地址或访问地址');
    return;
  }
  if (!formData.security_protection_level) {
    message.warning('请选择安全保护等级');
    return;
  }
  if (!formData.address && formData.ipv4) {
    formData.address = formData.ipv4;
  }
  formData.region_name = regionLabelFromCode(formData.region_code) || '';
  if (!formData.asset_subtype) {
    formData.asset_subtype = formData.type;
  }
  try {
    let assetId = editingId.value || '';
    if (editingId.value) {
      await updateAsset(editingId.value, formData as any);
      message.success('更新成功');
    } else {
      const created = normalizeItemResponse<Asset>(await createAsset(formData as any));
      assetId = created.id;
      message.success('创建成功');
    }
    if (assetId) {
      await saveAssetDynamicForm(assetId);
    }
    setAssetModalVisible(false);
    fetchList();
  } catch {
    message.error('操作失败');
  }
}

async function onDelete(id: string) {
  try { await deleteAsset(id); message.success('删除成功'); fetchList(); }
  catch { message.error('删除失败'); }
}

async function onBatchDelete() {
  if (!checkedKeys.value.length) { message.warning('请先选择资产'); return; }
  for (const id of checkedKeys.value) { await deleteAsset(id).catch(() => {}); }
  checkedKeys.value = []; message.success('批量删除完成'); fetchList();
}

function buildTarget(row: Asset): string {
  if (row.url) return row.url;
  if (row.domain) return row.port ? `${row.domain}:${row.port}` : row.domain;
  if (row.ipv4) return row.port ? `${row.ipv4}:${row.port}` : row.ipv4;
  return row.port ? `${row.address}:${row.port}` : row.address;
}

async function onScan(row: Asset) {
  try {
    await createTask({
      name: `扫描-${row.name || row.address}`,
      targets: [buildTarget(row)],
    });
    message.success('扫描任务已创建，请到扫描中心查看');
  } catch { message.error('创建扫描任务失败'); }
}

async function onBatchScan() {
  if (!checkedKeys.value.length) { message.warning('请先选择资产'); return; }
  const selected = data.value.filter(a => checkedKeys.value.includes(a.id));
  const targets = selected.map(buildTarget);
  try {
    await createTask({
      name: `批量扫描-${targets.length}个资产`,
      targets,
    });
    message.success(`已创建扫描任务，包含 ${targets.length} 个目标`);
  } catch { message.error('创建扫描任务失败'); }
}

async function onImportUpload(options: { file: UploadFileInfo }) {
  const rawFile = options.file.file;
  if (!rawFile) return;
  importLoading.value = true;
  try {
    const res: any = await importAssets(rawFile);
    const body = res?.data ?? res;
    const imported = body?.data?.imported ?? body?.imported ?? 0;
    message.success(`成功导入 ${imported} 条资产`);
    setImportVisible(false);
    fetchList();
  } catch { message.error('导入失败，请检查文件格式'); }
  finally { importLoading.value = false; }
}

async function downloadTemplate() {
  try {
    const blob = await requestClient.download<Blob>('/asset/import/template');
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'asset_import_template.xlsx';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch {
    message.error('下载模板失败');
  }
}

async function onSendToMonitor() {
  if (!checkedKeys.value.length) { message.warning('请先选择资产'); return; }
  sendingToMonitor.value = true;
  try {
    const res: any = await requestClient.post('/monitor/tasks/from-assets', {
      asset_ids: checkedKeys.value,
    });
    monitorResult.value = res?.data ?? res;
    setMonitorResultVisible(true);
    checkedKeys.value = [];
    message.success(`创建了 ${monitorResult.value?.success ?? 0} 个监测任务`);
  } catch (e: any) {
    message.error(e?.msg || '发送到站点监控失败');
  } finally {
    sendingToMonitor.value = false;
  }
}

async function onSubmitToVerify() {
  if (!checkedKeys.value.length) { message.warning('请先选择资产'); return; }
  submittingToVerify.value = true;
  try {
    const selectedIds = [...checkedKeys.value];
    await createVerifyTasks({
      asset_ids: selectedIds,
      source_type: 'manual',
      remark: '从资产台账一键提交核验',
    });
    checkedKeys.value = [];
    message.success(`已提交 ${selectedIds.length} 个资产到核验任务`);
    fetchList();
  } catch (e: any) {
    message.error(e?.msg || '提交核验失败');
  } finally {
    submittingToVerify.value = false;
  }
}

const batchEditFieldOptions = [
  { label: '系统类型', value: 'system_type' },
  { label: '保护等级', value: 'security_protection_level' },
  { label: '数据来源', value: 'data_source' },
  { label: '责任人', value: 'responsible_user_name' },
  { label: '状态(1活跃/0不活跃)', value: 'status' },
  { label: '是否关键资产', value: 'is_key' },
  { label: '备注', value: 'remark' },
];
const batchEditValueOptions = computed<Record<string, DictOption[]>>(() => ({
  system_type: systemTypeOptions.value,
  security_protection_level: securityOptions.value,
  data_source: sourceOptions.value,
  status: [{ label: '活跃', value: '1' }, { label: '不活跃', value: '0' }],
  is_key: [{ label: '是', value: 'true' }, { label: '否', value: 'false' }],
}));

function openBatchEdit() {
  if (!checkedKeys.value.length) { message.warning('请先选择资产'); return; }
  batchEditForm.field = '';
  batchEditForm.value = '';
  setBatchEditVisible(true);
}

async function onBatchEditConfirm() {
  if (!batchEditForm.field || !batchEditForm.value) { message.warning('请选择字段和值'); return; }
  batchEditLoading.value = true;
  let val: any = batchEditForm.value;
  if (batchEditForm.field === 'status') val = Number(val);
  if (batchEditForm.field === 'is_key') val = val === 'true';
  try {
    const res: any = await requestClient.post('/asset/batch-update', {
      ids: checkedKeys.value,
      updates: { [batchEditForm.field]: val },
    });
    const affected = res?.data?.affected ?? res?.affected ?? 0;
    message.success(`已更新 ${affected} 条资产`);
    setBatchEditVisible(false);
    checkedKeys.value = [];
    fetchList();
  } catch { message.error('批量编辑失败'); }
  finally { batchEditLoading.value = false; }
}

async function onExport() {
  exportLoading.value = true;
  try {
    const params: Record<string, string> = { format: 'xlsx' };
    if (searchForm.keyword) params.keyword = searchForm.keyword;
    if (searchForm.asset_family) params.asset_family = searchForm.asset_family;
    if (searchForm.system_type) params.system_type = searchForm.system_type;
    if (searchForm.region_code) params.region_code = searchForm.region_code;
    if (searchForm.security_protection_level) params.security_protection_level = searchForm.security_protection_level;
    if (searchForm.data_source) params.data_source = searchForm.data_source;

    const blob = await requestClient.download<Blob>('/asset/export', { params });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `assets_${new Date().toISOString().slice(0, 10)}.xlsx`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch {
    message.error('导出失败');
  } finally {
    exportLoading.value = false;
  }
}

interface OrgItem {
  id: string;
  name: string;
  parent_id?: string;
}

function buildTree(items: OrgItem[]): TreeOption[] {
  const map = new Map<string, TreeOption>();
  const roots: TreeOption[] = [];

  for (const item of items) {
    map.set(item.id, { children: [], key: item.id, label: item.name });
  }

  for (const item of items) {
    const node = map.get(item.id);
    if (!node) continue;
    if (item.parent_id && map.has(item.parent_id)) {
      map.get(item.parent_id)?.children?.push(node);
    } else {
      roots.push(node);
    }
  }

  return roots.map(pruneTreeNode);
}

function pruneTreeNode(node: TreeOption): TreeOption {
  if (node.children?.length) {
    return { ...node, children: node.children.map(pruneTreeNode) };
  }
  return { key: node.key, label: node.label };
}

async function fetchTree() {
  treeLoading.value = true;
  try {
    const res = await getOrganizeTree();
    const body = (res as any)?.data ?? res;
    const items: OrgItem[] = body?.data ?? body ?? [];
    orgTree.value = [
      { children: buildTree(items), key: '__all__', label: '全部单位' },
    ];
  } catch {
    orgTree.value = [{ key: '__all__', label: '全部单位' }];
  } finally {
    treeLoading.value = false;
  }
}

function onSelectOrg(keys: string[]) {
  const key = keys[0] ?? null;
  selectedOrgKey.value = key;
  searchForm.organize_id = key && key !== '__all__' ? key : undefined;
  pagination.page = 1;
  fetchList();
}

onMounted(() => {
  fetchList();
  loadReferenceOptions();
  loadDictOptions();
  fetchTree();
});
</script>

<template>
  <div class="asset-ledger-page">
    <NCard class="asset-ledger-page__tree" size="small">
      <template #header>
        <div class="org-tree-header">
          <span class="org-tree-title">单位筛选</span>
          <span class="org-tree-desc">按所属单位过滤资产列表</span>
        </div>
      </template>
      <NTree
        v-if="orgTree.length"
        :data="orgTree"
        :default-expanded-keys="['__all__']"
        :selected-keys="selectedOrgKey ? [selectedOrgKey] : []"
        block-line
        selectable
        @update:selected-keys="onSelectOrg"
      />
      <NEmpty v-else description="暂无单位数据" size="small" />
    </NCard>

    <div class="asset-ledger-page__main">
    <NCard class="asset-ledger-card" title="资产台账" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NButton type="primary" size="small" @click="onAdd">
            <template #icon><Plus size="16" /></template>
            登记资产
          </NButton>
          <NButton size="small" @click="setImportVisible(true)">
            <template #icon><Upload size="16" /></template>
            导入
          </NButton>
          <NButton size="small" :loading="exportLoading" @click="onExport">
            <template #icon><Download size="16" /></template>
            导出
          </NButton>
          <NDropdown
            :options="batchOptions"
            @select="handleBatchSelect"
          >
            <NButton size="small">
              <template #icon><MoreHorizontal size="16" /></template>
              批量操作{{ checkedKeys.length ? ` (${checkedKeys.length})` : '' }}
            </NButton>
          </NDropdown>
        </NSpace>
      </template>

      <div class="asset-tabs">
        <NSpace :size="4" wrap>
          <NButton
            v-for="view in [
              { key: 'all', label: '全部', icon: Server },
              { key: 'ip', label: 'IP资产', icon: Globe },
              { key: 'domain_site', label: '域名网站', icon: Globe },
              { key: 'business_system', label: '业务系统', icon: Server },
              { key: 'hardware', label: '硬件设备', icon: Server },
              { key: 'software', label: '软件资产', icon: Activity },
            ]"
            :key="view.key"
            :type="familyViewButtonType(view.key as any)"
            size="small"
            class="asset-tab-btn"
            @click="changeFamilyView(view.key as any)"
          >
            <component :is="view.icon" size="14" />
            {{ view.label }}
          </NButton>
        </NSpace>
      </div>

      <NGrid :cols="5" :x-gap="12" responsive="screen" class="stats-grid">
        <NGridItem>
          <div class="stat-card">
            <div class="stat-icon stat-icon--indigo">
              <Server size="20" />
            </div>
            <div class="stat-content">
              <div class="stat-value">{{ stats.total }}</div>
              <div class="stat-label">资产总数</div>
            </div>
          </div>
        </NGridItem>
        <NGridItem>
          <div class="stat-card">
            <div class="stat-icon stat-icon--emerald">
              <CheckCircle2 size="20" />
            </div>
            <div class="stat-content">
              <div class="stat-value">{{ stats.online }}</div>
              <div class="stat-label">在线资产</div>
            </div>
          </div>
        </NGridItem>
        <NGridItem>
          <div class="stat-card">
            <div class="stat-icon stat-icon--indigo">
              <ShieldAlert size="20" />
            </div>
            <div class="stat-content">
              <div class="stat-value">{{ stats.keyAssets }}</div>
              <div class="stat-label">关键资产</div>
            </div>
          </div>
        </NGridItem>
        <NGridItem>
          <div class="stat-card">
            <div class="stat-icon stat-icon--red">
              <AlertTriangle size="20" />
            </div>
            <div class="stat-content">
              <div class="stat-value">{{ stats.riskHigh }}</div>
              <div class="stat-label">高风险</div>
            </div>
          </div>
        </NGridItem>
        <NGridItem>
          <div class="stat-card">
            <div class="stat-icon stat-icon--amber">
              <ShieldAlert size="20" />
            </div>
            <div class="stat-content">
              <div class="stat-value">{{ stats.withVulns }}</div>
              <div class="stat-label">有漏洞</div>
            </div>
          </div>
        </NGridItem>
      </NGrid>

      <NCard v-if="expiredSslAssets.length || expiredDomainAssets.length || expiringSslAssets.length || expiringDomainAssets.length" size="small" type="warning" class="alert-card">
        <NSpace vertical :size="8">
          <div v-if="expiredSslAssets.length">
            <span class="alert-title alert-title--error">SSL证书已过期 ({{ expiredSslAssets.length }})：</span>
            <NSpace wrap :size="4" class="alert-tags">
              <NTag v-for="item in expiredSslAssets" :key="item.id" type="error" size="small" class="alert-tag" @click="router.push(`/asset/detail/${item.id}`)">
                {{ item.name || '-' }}
              </NTag>
            </NSpace>
          </div>
          <div v-if="expiredDomainAssets.length">
            <span class="alert-title alert-title--error">域名已过期 ({{ expiredDomainAssets.length }})：</span>
            <NSpace wrap :size="4" class="alert-tags">
              <NTag v-for="item in expiredDomainAssets" :key="item.id" type="error" size="small" class="alert-tag" @click="router.push(`/asset/detail/${item.id}`)">
                {{ item.name || '-' }}
              </NTag>
            </NSpace>
          </div>
          <div v-if="expiringSslAssets.length">
            <span class="alert-title alert-title--warning">SSL证书即将过期 ({{ expiringSslAssets.length }})：</span>
            <NSpace wrap :size="4" class="alert-tags">
              <NTag v-for="item in expiringSslAssets" :key="item.id" type="warning" size="small" class="alert-tag" @click="router.push(`/asset/detail/${item.id}`)">
                {{ item.name || '-' }} ({{ item.ssl_expires_at?.slice(0, 10) }})
              </NTag>
            </NSpace>
          </div>
          <div v-if="expiringDomainAssets.length">
            <span class="alert-title alert-title--warning">域名即将过期 ({{ expiringDomainAssets.length }})：</span>
            <NSpace wrap :size="4" class="alert-tags">
              <NTag v-for="item in expiringDomainAssets" :key="item.id" type="warning" size="small" class="alert-tag" @click="router.push(`/asset/detail/${item.id}`)">
                {{ item.name || '-' }} ({{ item.domain_expires_at?.slice(0, 10) }})
              </NTag>
            </NSpace>
          </div>
        </NSpace>
      </NCard>

      <div class="filter-section">
        <div class="filter-row">
          <NForm inline label-placement="left" :show-feedback="false" class="filter-form">
            <NFormItem label="关键词">
              <NInput v-model:value="searchForm.keyword" placeholder="名称/地址" clearable style="width: 180px">
                <template #prefix><Search size="14" /></template>
              </NInput>
            </NFormItem>
            <NFormItem label="编号">
              <NInput v-model:value="searchForm.data_number" placeholder="数据编号" clearable style="width: 140px" />
            </NFormItem>
            <NFormItem label="类型">
              <NSelect v-model:value="searchForm.system_type" :options="systemTypeOptions" placeholder="全部" clearable style="width: 120px" />
            </NFormItem>
            <NFormItem label="地域">
              <NCascader v-model:value="searchForm.region_code" :options="regionOptions" clearable placeholder="全部" style="width: 190px" check-strategy="child" />
            </NFormItem>
            <NFormItem label="等保">
              <NSelect v-model:value="searchForm.security_protection_level" :options="securityOptions" placeholder="全部" clearable style="width: 100px" />
            </NFormItem>
            <NFormItem>
              <NSpace :size="8">
                <NButton type="primary" size="small" @click="onSearch">
                  <template #icon><Search size="14" /></template>
                  查询
                </NButton>
                <NButton size="small" @click="onReset">重置</NButton>
                <NButton text type="info" size="small" @click="showAdvancedFilter = !showAdvancedFilter">
                  {{ showAdvancedFilter ? '收起' : '高级筛选' }}
                </NButton>
              </NSpace>
            </NFormItem>
          </NForm>
        </div>

        <div v-if="showAdvancedFilter" class="advanced-filter">
          <NForm inline label-placement="left" :show-feedback="false">
            <NFormItem label="风险分≥">
              <NInputNumber v-model:value="searchForm.risk_score_min" :min="0" :max="100" placeholder="最低" style="width: 100px" />
            </NFormItem>
            <NFormItem label="风险分≤">
              <NInputNumber v-model:value="searchForm.risk_score_max" :min="0" :max="100" placeholder="最高" style="width: 100px" />
            </NFormItem>
            <NFormItem label="关键资产">
              <NSelect v-model:value="searchForm.is_key" :options="[{ label: '是', value: 'true' }, { label: '否', value: 'false' }]" placeholder="全部" clearable style="width: 100px" />
            </NFormItem>
            <NFormItem label="数据来源">
              <NSelect v-model:value="searchForm.data_source" :options="sourceOptions" placeholder="全部" clearable style="width: 120px" />
            </NFormItem>
          </NForm>
        </div>
      </div>

      <NDataTable v-model:checked-row-keys="checkedKeys" :columns="visibleColumns" :data="data" :loading="loading"
        :pagination="pagination" :row-key="(row: Asset) => row.id" :bordered="false" :scroll-x="1500" size="small" striped remote />
    </NCard>

    <!-- 登记/编辑 -->
    <NModal
      v-model:show="showModal"
      class="asset-modal"
      preset="dialog"
      :title="editingId ? '编辑资产' : '资产登记'"
      style="width: min(960px, calc(100vw - 32px)); max-height: calc(100dvh - 32px)"
      @update:show="setAssetModalVisible"
    >
      <div class="asset-modal-body">
        <NForm class="asset-form" label-placement="left" label-width="132">
        <div class="asset-form-section">
          <div class="asset-section-title">资产信息</div>
          <NGrid :cols="2" :x-gap="16">
          <NGridItem><NFormItem label="系统名称" required><NInput v-model:value="formData.name" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="所属单位" required><NSelect v-model:value="formData.organize_id" :options="organizeOptions" filterable clearable /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="系统类型" required><NSelect v-model:value="formData.system_type" :options="systemTypeOptions" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="是否联网" required><NSwitch v-model:value="formData.is_online" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="IPV4地址" required><NInput v-model:value="formData.ipv4" placeholder="多个用逗号分隔" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="IPV6地址"><NInput v-model:value="formData.ipv6" placeholder="无则留空" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="网址"><NInput v-model:value="formData.url" placeholder="https://example.com" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="是否关键基础设施"><NSwitch v-model:value="formData.is_key" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="安全保护等级" required><NSelect v-model:value="formData.security_protection_level" :options="securityOptions" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="备案证明编号"><NInput v-model:value="formData.filing_cert_number" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="ICP备案号"><NInput v-model:value="formData.icp_filing_number" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="公网安备案号"><NInput v-model:value="formData.public_security_filing" /></NFormItem></NGridItem>
          <NGridItem v-if="showAddressFields"><NFormItem label="地址" required><NInput v-model:value="formData.address" /></NFormItem></NGridItem>
          <NGridItem v-if="showPortField"><NFormItem label="端口"><NInputNumber v-model:value="formData.port" :min="0" :max="65535" style="width: 100%" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="资产分类"><NSelect :value="formData.asset_family" :options="assetFamilyOptions" @update:value="onAssetFamilyChange" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="资产子类"><NSelect v-model:value="formData.asset_subtype" :options="assetSubtypeOptions" clearable /></NFormItem></NGridItem>
          <NGridItem v-if="showTypeField"><NFormItem label="资产类型"><NSelect v-model:value="formData.type" :options="assetTypeOptions" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="地域"><NCascader v-model:value="formData.region_code" :options="regionOptions" clearable check-strategy="child" /></NFormItem></NGridItem>
          <NGridItem v-if="showConstructionFields">
            <NFormItem label="建设单位">
              <NSpace vertical :size="6" style="width: 100%">
                <NSelect v-model:value="formData.construction_org_id" :options="constructionOptions" filterable clearable />
                <NSpace :size="8">
                  <NButton size="tiny" text type="primary" @click="openQuickConstruction('construction')">快速新增</NButton>
                  <NButton size="tiny" text :disabled="!formData.operation_org_id" @click="useOperationAsConstruction">同运维单位</NButton>
                </NSpace>
              </NSpace>
            </NFormItem>
          </NGridItem>
          <NGridItem v-if="showConstructionFields">
            <NFormItem label="运维单位">
              <NSpace vertical :size="6" style="width: 100%">
                <NSelect v-model:value="formData.operation_org_id" :options="constructionOptions" filterable clearable />
                <NSpace :size="8">
                  <NButton size="tiny" text type="primary" @click="openQuickConstruction('operation')">快速新增</NButton>
                  <NButton size="tiny" text :disabled="!formData.construction_org_id" @click="useConstructionAsOperation">同建设单位</NButton>
                </NSpace>
              </NSpace>
            </NFormItem>
          </NGridItem>
          <NGridItem><NFormItem label="数据来源"><NSelect v-model:value="formData.data_source" :options="sourceOptions" /></NFormItem></NGridItem>
          <NGridItem v-if="showResponsibleField"><NFormItem label="责任人"><NInput v-model:value="formData.responsible_user_name" /></NFormItem></NGridItem>
          <NGridItem span="2"><NFormItem label="备注"><NInput v-model:value="formData.remark" type="textarea" :rows="2" /></NFormItem></NGridItem>
          </NGrid>
        </div>

        <div class="asset-form-section">
          <div class="asset-section-title">
            <span>单位补充信息</span>
            <NButton size="tiny" text type="primary" @click="showUnitExtraFields = !showUnitExtraFields">
              {{ showUnitExtraFields ? '收起' : '展开填写' }}
            </NButton>
          </div>
          <NGrid v-if="showUnitExtraFields" :cols="2" :x-gap="16">
            <NGridItem><NFormItem label="单位类型"><NInput v-model:value="formData.extra.unit_type" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="行业分类"><NInput v-model:value="formData.extra.industry_category" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="通报机制成员单位"><NSwitch v-model:value="formData.extra.is_notification_member" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="统一社会信用代码"><NInput v-model:value="formData.extra.unified_social_credit_code" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="单位地址"><NInput v-model:value="formData.extra.unit_address" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="单位详细地址"><NInput v-model:value="formData.extra.unit_detail_address" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="分管领导姓名"><NInput v-model:value="formData.extra.leader_name" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="分管领导职务/职称"><NInput v-model:value="formData.extra.leader_title" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="责任部门名称"><NInput v-model:value="formData.extra.responsible_department_name" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="责任部门负责人姓名"><NInput v-model:value="formData.extra.department_leader_name" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="负责人职务/职称"><NInput v-model:value="formData.extra.department_leader_title" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="负责人电话"><NInput v-model:value="formData.extra.department_leader_phone" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="联系人姓名"><NInput v-model:value="formData.extra.contact_name" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="联系人职务/职称"><NInput v-model:value="formData.extra.contact_title" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="联系人电话"><NInput v-model:value="formData.extra.contact_phone" /></NFormItem></NGridItem>
          </NGrid>
        </div>

        <div v-if="assetDynamicTemplate" class="asset-form-section">
          <div class="asset-section-title">
            <span>动态扩展信息</span>
            <NTag size="small" :bordered="false" type="info">
              {{ assetDynamicTemplate.name }}
            </NTag>
          </div>
          <div class="asset-dynamic-form-shell">
            <DynamicFormRenderer
              v-model="assetDynamicFormData"
              :schema="assetDynamicSubmission?.version?.schema || assetDynamicTemplate.schema"
              :options="assetDynamicRenderOptions"
            />
          </div>
        </div>

        </NForm>
      </div>
      <template #action><NSpace><NButton @click="setAssetModalVisible(false)">取消</NButton><NButton type="primary" @click="onSaveWithDynamicForm">确认</NButton></NSpace></template>
    </NModal>

    <!-- 快速新增建设运维单位 -->
    <NModal
      v-model:show="showQuickConstructionModal"
      class="asset-modal asset-quick-modal"
      preset="dialog"
      title="快速新增建设运维单位"
      style="width: min(740px, calc(100vw - 32px)); max-height: calc(100dvh - 32px)"
      @update:show="setQuickConstructionVisible"
    >
      <div class="asset-modal-body asset-quick-modal-body">
        <NForm class="asset-quick-form" label-placement="left" label-width="108" :show-feedback="false">
          <div class="asset-quick-section">
            <span>基础信息</span>
          </div>
          <NGrid :cols="12" :x-gap="16" :y-gap="0">
            <NGridItem :span="6">
              <NFormItem label="单位名称" required>
                <NInput v-model:value="quickConstructionForm.name" placeholder="请输入单位名称" />
              </NFormItem>
            </NGridItem>
            <NGridItem :span="6">
              <NFormItem label="所在地">
                <NCascader
                  v-model:value="quickConstructionForm.location_code"
                  :options="regionOptions"
                  filterable
                  clearable
                  check-strategy="child"
                  placeholder="请选择省/市/区县"
                />
              </NFormItem>
            </NGridItem>
            <NGridItem :span="12">
              <NFormItem label="详细地址">
                <NInput v-model:value="quickConstructionForm.address" placeholder="请输入详细办公地址，可具体到门牌号" />
              </NFormItem>
            </NGridItem>
          </NGrid>

          <div class="asset-quick-section">
            <span>联系人信息</span>
          </div>
          <NGrid :cols="12" :x-gap="16" :y-gap="0">
            <NGridItem :span="6">
              <NFormItem label="负责人及职务">
                <NInput v-model:value="quickConstructionForm.charge_person" placeholder="请输入负责人及职务" />
              </NFormItem>
            </NGridItem>
            <NGridItem :span="6">
              <NFormItem label="联系电话">
                <NInput v-model:value="quickConstructionForm.charge_phone" placeholder="请输入联系电话" />
              </NFormItem>
            </NGridItem>
            <NGridItem :span="12">
              <NFormItem label="公网安备案号">
                <NInput v-model:value="quickConstructionForm.security_filing" placeholder="请输入公网安备案号" />
              </NFormItem>
            </NGridItem>
            <NGridItem :span="12">
              <div class="asset-quick-switch-row">
                <NSwitch v-model:value="linkQuickConstructionToBoth" />
                <div class="asset-quick-switch-text">
                  <div>同时作为建设和运维单位</div>
                  <span>适用于同一单位同时承担建设与运维职责的场景</span>
                </div>
              </div>
            </NGridItem>
          </NGrid>
        </NForm>
      </div>
      <template #action>
        <NSpace>
          <NButton @click="setQuickConstructionVisible(false)">取消</NButton>
          <NButton type="primary" @click="onQuickConstructionSave">确认新增</NButton>
        </NSpace>
      </template>
    </NModal>

    <NModal v-model:show="showBatchEdit" preset="dialog" title="批量编辑" style="width: 460px" @update:show="setBatchEditVisible">
      <div style="margin-top: 12px">
        <p style="margin-bottom: 12px; color: #666">将对选中的 {{ checkedKeys.length }} 个资产进行统一修改。</p>
        <NForm label-placement="left" label-width="80" :show-feedback="false">
          <NFormItem label="修改字段">
            <NSelect v-model:value="batchEditForm.field" :options="batchEditFieldOptions" placeholder="选择字段" />
          </NFormItem>
          <NFormItem label="目标值" style="margin-top: 12px">
            <NSelect v-if="batchEditValueOptions[batchEditForm.field]" v-model:value="batchEditForm.value" :options="batchEditValueOptions[batchEditForm.field]" placeholder="选择值" />
            <NInput v-else v-model:value="batchEditForm.value" placeholder="输入值" />
          </NFormItem>
        </NForm>
      </div>
      <template #action>
        <NSpace>
          <NButton @click="setBatchEditVisible(false)">取消</NButton>
          <NButton type="primary" :loading="batchEditLoading" @click="onBatchEditConfirm">确认修改</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- 导入弹窗 -->
    <NModal v-model:show="showImport" preset="dialog" title="导入资产" style="width: 500px" @update:show="setImportVisible">
      <div style="margin-top: 16px">
        <p style="margin-bottom: 12px; color: var(--n-text-color-3)">支持 .csv 和 .xlsx 格式，请按模板填写数据后上传。字典字段可填写中文标签或实际值。</p>
        <NSpace vertical :size="16">
          <NButton text type="primary" @click="downloadTemplate">下载导入模板 (xlsx)</NButton>
          <NUpload
            :max="1"
            accept=".csv,.xlsx"
            :custom-request="({ file }: any) => onImportUpload({ file })"
            :show-file-list="false"
          >
            <NButton type="primary" :loading="importLoading">{{ importLoading ? '导入中...' : '选择文件上传' }}</NButton>
          </NUpload>
        </NSpace>
      </div>
    </NModal>

    <!-- 发送到站点监控结果 -->
    <NModal v-model:show="monitorResultVisible" preset="card" title="发送到站点监控" style="width: 540px" @update:show="setMonitorResultVisible">
      <template v-if="monitorResult">
        <NGrid :cols="3" :x-gap="8" style="margin-bottom: 12px">
          <NGridItem><NCard size="small"><NStatistic label="成功创建" :value="monitorResult.success ?? 0" /></NCard></NGridItem>
          <NGridItem><NCard size="small"><NStatistic label="已存在跳过" :value="monitorResult.skipped ?? 0" /></NCard></NGridItem>
          <NGridItem><NCard size="small"><NStatistic label="失败" :value="monitorResult.failed ?? 0" /></NCard></NGridItem>
        </NGrid>
        <NDataTable
          v-if="monitorResult.details?.length"
          :columns="[
            { title: '资产', key: 'asset_name', ellipsis: { tooltip: true } },
            {
              title: '结果',
              key: 'status',
              width: 100,
              render: (row: any) => h(NTag, { type: row.status === 'success' ? 'success' : row.status === 'skipped' ? 'warning' : 'error', size: 'small' }, () => row.status === 'success' ? '成功' : row.status === 'skipped' ? '跳过' : '失败'),
            },
            { title: '说明', key: 'reason', ellipsis: { tooltip: true } },
          ]"
          :data="monitorResult.details"
          :bordered="false"
          size="small"
          :max-height="300"
        />
      </template>
      <template #action><NButton @click="setMonitorResultVisible(false)">关闭</NButton></template>
    </NModal>
    </div>
  </div>
</template>

<style scoped>
.asset-ledger-page {
  display: flex;
  gap: 16px;
  padding: 16px;
  height: calc(100vh - 64px);
}

.asset-ledger-page__tree {
  width: 240px;
  flex-shrink: 0;
  overflow-y: auto;
}

.org-tree-header {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.org-tree-title {
  font-size: 14px;
  font-weight: 600;
}

.org-tree-desc {
  font-size: 11px;
  color: var(--n-text-color-3);
}

.asset-ledger-page__main {
  flex: 1;
  min-width: 0;
  overflow-y: auto;
}

.stat-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  vertical-align: middle;
}

.stat-dot--success {
  background-color: #18a058;
}

.stat-symbol {
  font-size: 14px;
  vertical-align: middle;
}

.stat-symbol--primary {
  color: #2080f0;
}

.stat-symbol--danger {
  color: #d03050;
}

.stat-symbol--warning {
  color: #f0a020;
}

:deep(.asset-modal .n-dialog) {
  display: flex;
  flex-direction: column;
  max-height: calc(100dvh - 32px);
}

:deep(.asset-modal .n-dialog__content) {
  display: flex;
  flex-direction: column;
  max-height: calc(100dvh - 120px);
  min-height: 0;
  overflow: hidden;
}

:deep(.asset-modal .n-dialog__action) {
  flex: 0 0 auto;
  margin: 12px -8px 0;
  padding: 12px 8px 0;
  border-top: 1px solid var(--n-border-color);
}

.asset-modal-body {
  flex: 1 1 auto;
  min-height: 0;
  max-height: calc(100dvh - 230px);
  overflow: auto;
  overscroll-behavior: contain;
  padding: 2px 10px 0 0;
  scrollbar-gutter: stable;
}

.asset-quick-modal :deep(.n-dialog) {
  width: min(740px, calc(100vw - 32px));
}

.asset-quick-modal-body {
  max-height: calc(100dvh - 180px);
  padding: 2px 4px 0 0;
}

.asset-quick-section {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 4px 0 14px;
  color: var(--n-text-color);
  font-size: 14px;
  font-weight: 600;
}

.asset-quick-section::before {
  width: 3px;
  height: 14px;
  border-radius: 2px;
  background: var(--n-icon-color);
  content: '';
}

.asset-quick-form .asset-quick-section:not(:first-child) {
  margin-top: 4px;
  padding-top: 14px;
  border-top: 1px solid var(--n-border-color);
}

.asset-quick-form :deep(.n-form-item) {
  margin-bottom: 12px;
}

.asset-quick-form :deep(.n-form-item-label) {
  align-items: center;
  color: var(--n-text-color);
  font-weight: 500;
}

.asset-quick-form :deep(.n-input),
.asset-quick-form :deep(.n-base-selection) {
  width: 100%;
}

.asset-quick-switch-row {
  display: flex;
  align-items: center;
  gap: 12px;
  min-height: 52px;
  margin: 0 0 4px 108px;
  padding: 8px 12px;
  color: var(--n-text-color);
  border: 1px solid var(--n-border-color);
  border-radius: 6px;
  background: var(--n-color);
}

.asset-quick-switch-text {
  min-width: 0;
  line-height: 1.35;
}

.asset-quick-switch-text span {
  display: block;
  margin-top: 3px;
  color: var(--n-text-color-3);
  font-size: 12px;
}

.asset-form {
  padding-top: 4px;
}

.asset-form-section {
  padding: 14px 0 2px;
  border-top: 1px solid var(--n-border-color);
}

.asset-form-section:first-child {
  padding-top: 0;
  border-top: 0;
}

.asset-section-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
  color: var(--n-text-color);
  font-size: 14px;
  font-weight: 600;
}

.asset-dynamic-form-shell {
  padding: 16px 18px 4px;
  border: 1px solid var(--n-border-color);
  border-radius: 10px;
  background: var(--n-color-embedded, var(--n-color));
}

.asset-dynamic-form-shell :deep(.form-create) {
  padding: 0;
}

.asset-dynamic-form-shell :deep(.fc-form) {
  display: block;
}

.asset-dynamic-form-shell :deep(.fc-form .n-form-item) {
  margin-bottom: 14px;
}

.asset-dynamic-form-shell :deep(.fc-form .n-form-item:last-child) {
  margin-bottom: 0;
}

.asset-detail-section :deep(.n-descriptions-table-content__label) {
  width: 168px;
}

@media (max-width: 720px) {
  .asset-quick-form :deep(.n-grid) {
    grid-template-columns: minmax(0, 1fr) !important;
  }

  .asset-quick-switch-row {
    margin-left: 0;
  }

  .asset-form :deep(.n-grid) {
    grid-template-columns: minmax(0, 1fr) !important;
  }

  .asset-form :deep(.n-form-item-label) {
    min-width: 112px;
  }
}

.asset-ledger-card {
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
}

.asset-tabs {
  padding: 8px 0 16px;
  border-bottom: 1px solid var(--n-border-color-split);
  margin-bottom: 16px;
}

.asset-tab-btn {
  border-radius: 6px;
  transition: all 0.2s ease;
}

.asset-tab-btn:hover {
  transform: translateY(-1px);
}

.stats-grid {
  margin-bottom: 16px;
}

.stat-card {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px;
  border-radius: 10px;
  background: var(--n-color-embedded, var(--n-color));
  border: 1px solid var(--n-border-color);
  border-left: 3px solid var(--n-border-color);
  transition: all 0.2s ease;
}

.stat-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
}

.stat-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 44px;
  height: 44px;
  border-radius: 10px;
  color: var(--n-text-color-3);
  background: var(--n-color-embedded, var(--n-color));
  transition: all 0.2s ease;
}

.stat-icon--indigo {
  color: #6366f1;
  background: rgba(99, 102, 241, 0.08);
}

.stat-icon--emerald {
  color: #10b981;
  background: rgba(16, 185, 129, 0.08);
}

.stat-icon--red {
  color: #ef4444;
  background: rgba(239, 68, 68, 0.08);
}

.stat-icon--amber {
  color: #f59e0b;
  background: rgba(245, 158, 11, 0.08);
}

.stat-content {
  flex: 1;
  min-width: 0;
}

.stat-value {
  font-size: 24px;
  font-weight: 700;
  line-height: 1.2;
  color: var(--n-text-color);
}

.stat-label {
  font-size: 13px;
  color: var(--n-text-color-3);
  margin-top: 2px;
}

.alert-card {
  margin-bottom: 16px;
  border-left: 4px solid #F59E0B;
}

.alert-title {
  font-weight: 600;
}

.alert-title--error {
  color: #d03050;
}

.alert-title--warning {
  color: #f0a020;
}

.alert-tags {
  display: inline-flex;
  vertical-align: middle;
}

.alert-tag {
  cursor: pointer;
  transition: all 0.2s ease;
}

.alert-tag:hover {
  transform: translateY(-1px);
}

.filter-section {
  margin-bottom: 16px;
}

.filter-row {
  padding: 12px 16px;
  background: var(--n-color-embedded, var(--n-color));
  border-radius: 8px;
  border: 1px solid var(--n-border-color);
}

.filter-form :deep(.n-form-item) {
  margin-bottom: 0;
}

.advanced-filter {
  margin-top: 12px;
  padding: 12px 16px;
  background: var(--n-color-embedded, var(--n-color));
  border-radius: 8px;
  border: 1px dashed var(--n-border-color);
  animation: slideDown 0.2s ease;
}

@keyframes slideDown {
  from {
    opacity: 0;
    transform: translateY(-8px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.asset-ledger-page :deep(.n-card__header) {
  padding-bottom: 12px;
  border-bottom: 1px solid var(--n-border-color-split);
}

.asset-ledger-page :deep(.n-data-table) {
  border-radius: 8px;
}

.asset-ledger-page :deep(.n-data-table-th) {
  background: var(--n-color-embedded, var(--n-color));
}

.asset-ledger-page :deep(.n-data-table-tr:hover .n-data-table-td) {
  background: var(--n-color-hover);
}

.asset-ledger-page :deep(.n-button--quaternary) {
  border-radius: 6px;
  transition: all 0.2s ease;
}

.asset-ledger-page :deep(.n-button--quaternary:hover) {
  transform: translateY(-1px);
}
</style>
