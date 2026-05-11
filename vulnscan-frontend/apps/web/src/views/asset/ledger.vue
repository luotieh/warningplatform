<script lang="ts" setup>
import { computed, h, onMounted, reactive, ref } from 'vue';
import {
  NButton, NCard, NCascader, NDataTable, NDescriptions, NDescriptionsItem, NDrawer, NDrawerContent,
  NForm, NFormItem, NGrid, NGridItem, NInput, NInputNumber, NModal, NPopconfirm,
  NSelect, NSpace, NSwitch, NTabPane, NTabs, NTag, NUpload, useMessage,
} from 'naive-ui';
import type { UploadFileInfo } from 'naive-ui';
import { NStatistic } from 'naive-ui';
import { useRouter } from 'vue-router';
import type { Asset } from '#/api/asset';
import {
  createAsset,
  deleteAsset,
  getAssetDetail,
  getAssetEnrich,
  getAssetList,
  importAssets,
  updateAsset,
} from '#/api/asset';
import type { ConstructionOrg } from '#/api/assetmgr';
import { createConstruction, createVerifyTasks, getConstructionList } from '#/api/assetmgr';
import { getPermissionApi } from '#/api/core/auth';
import type { DynamicFormSubmissionDetail, DynamicFormTemplate } from '#/api/form';
import {
  getDynamicFormSubmission,
  getDynamicFormSubmissions,
  getDynamicFormTemplates,
  normalizePagedResponse,
  saveDynamicFormSubmission,
} from '#/api/form';
import { dictItemsToOptions, getSystemDictItems } from '#/api/system/dict';
import { createTask } from '#/api/task';
import { requestClient } from '#/api/request';
import { regionLabelFromCode, regionOptions } from '#/utils/region';
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
const showDetail = ref(false);
const showImport = ref(false);
const importLoading = ref(false);
const editingId = ref<null | string>(null);
const detailItem = ref<Asset | null>(null);
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

function setDetailVisible(visible: boolean) {
  setOverlayVisible(showDetail, visible);
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
  lifecycle_state: undefined as string | undefined, data_source: undefined as string | undefined,
});

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
type ExtraKey = keyof AssetExtra;

const formData = reactive({
  name: '', type: 'server', address: '', port: 0, domain: '', ipv4: '', ipv6: '', url: '', protocol: '',
  service: '', version: '', os: '', data_number: '', system_name: '', system_type: '',
  is_online: true, is_key: false, security_protection_level: '', filing_cert_number: '',
  icp_filing_number: '', organize_id: '', construction_org_id: '', operation_org_id: '', data_source: 'manual_import',
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

const assetInfoFields = [
  { label: '系统名称', key: 'system_name' },
  { label: '系统类型', key: 'system_type', map: systemTypeLabel },
  { label: '是否联网', key: 'is_online', map: booleanLabel },
  { label: 'IPv4地址', key: 'ipv4' },
  { label: 'IPv6地址', key: 'ipv6' },
  { label: '网址', key: 'url' },
  { label: '是否是关键信息基础设施', key: 'is_key', map: booleanLabel },
  { label: '安全保护等级', key: 'security_protection_level', map: securityLabel },
  { label: '备案证明编号', key: 'filing_cert_number' },
  { label: 'ICP备案号', key: 'icp_filing_number' },
] as const;

const unitInfoFields = [
  { label: '单位类型', key: 'unit_type' },
  { label: '行业分类', key: 'industry_category' },
  { label: '是否是通报机制成员单位', key: 'is_notification_member', map: booleanLabel },
  { label: '统一社会信用代码', key: 'unified_social_credit_code' },
  { label: '单位地址', key: 'unit_address' },
  { label: '单位详细地址', key: 'unit_detail_address' },
  { label: '分管领导姓名', key: 'leader_name' },
  { label: '分管领导职务/职称', key: 'leader_title' },
  { label: '责任部门名称', key: 'responsible_department_name' },
  { label: '责任部门负责人姓名', key: 'department_leader_name' },
  { label: '负责人职务/职称', key: 'department_leader_title' },
  { label: '负责人电话', key: 'department_leader_phone' },
  { label: '联系人姓名', key: 'contact_name' },
  { label: '联系人职务/职称', key: 'contact_title' },
  { label: '联系人电话', key: 'contact_phone' },
] as const;

type DictOption = { label: string; value: string };

const defaultSystemTypeOptions: DictOption[] = [
  { label: '网站', value: 'url' }, { label: '应用系统', value: 'application' },
  { label: '数据库', value: 'database' }, { label: '服务器', value: 'server' },
  { label: '网络设备', value: 'network' }, { label: '安全设备', value: 'security' },
];
const defaultAssetTypeOptions: DictOption[] = [...defaultSystemTypeOptions];
const defaultSecurityOptions: DictOption[] = [
  { label: '一级', value: 'level1' }, { label: '二级', value: 'level2' },
  { label: '三级', value: 'level3' }, { label: '四级', value: 'level4' }, { label: '五级', value: 'level5' },
];
const defaultSourceOptions: DictOption[] = [
  { label: '手动导入', value: 'manual_import' }, { label: '自动探测', value: 'auto_detect' },
  { label: '外部集成', value: 'external' },
];
const lifecycleOptions = [
  { label: '已发现', value: 'discovered' }, { label: '已确认', value: 'confirmed' },
  { label: '已登记', value: 'registered' }, { label: '运营中', value: 'operating' },
  { label: '退役中', value: 'decommission' }, { label: '已下线', value: 'offline' },
];

const systemTypeOptions = ref<DictOption[]>([...defaultSystemTypeOptions]);
const assetTypeOptions = ref<DictOption[]>([...defaultAssetTypeOptions]);
const securityOptions = ref<DictOption[]>([...defaultSecurityOptions]);
const sourceOptions = ref<DictOption[]>([...defaultSourceOptions]);

const systemTypeMap = computed<Record<string, string>>(() => Object.fromEntries(systemTypeOptions.value.map(o => [o.value, o.label])));
const assetTypeMap = computed<Record<string, string>>(() => Object.fromEntries(assetTypeOptions.value.map(o => [o.value, o.label])));
const securityMap = computed<Record<string, string>>(() => Object.fromEntries(securityOptions.value.map(o => [o.value, o.label])));
const sourceMap = computed<Record<string, string>>(() => Object.fromEntries(sourceOptions.value.map(o => [o.value, o.label])));
const lifecycleMap: Record<string, { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
  discovered: { label: '已发现', type: 'default' }, confirmed: { label: '已确认', type: 'info' },
  registered: { label: '已登记', type: 'info' }, operating: { label: '运营中', type: 'success' },
  decommission: { label: '退役中', type: 'warning' }, offline: { label: '已下线', type: 'error' },
};

function booleanLabel(value: unknown) {
  return value === true ? '是' : value === false ? '否' : '-';
}

function systemTypeLabel(value: unknown) {
  const key = String(value ?? '');
  return systemTypeMap.value[key] || key || '-';
}

function assetTypeLabel(value: unknown) {
  const key = String(value ?? '');
  return assetTypeMap.value[key] || key || '-';
}

function securityLabel(value: unknown) {
  const key = String(value ?? '');
  return securityMap.value[key] || key || '-';
}

function textLabel(value: unknown) {
  if (value === undefined || value === null || value === '') return '-';
  return String(value);
}

function mergeExtra(extra?: Record<string, any> | null): AssetExtra {
  return { ...extraDefaults, ...(extra ?? {}) };
}

function extraText(asset: Asset | null, key: ExtraKey, map?: (value: unknown) => string) {
  const value = asset?.extra?.[key];
  return map ? map(value) : textLabel(value);
}

function assetText(asset: Asset | null, key: keyof Asset, map?: (value: unknown) => string) {
  const value = asset?.[key];
  return map ? map(value) : textLabel(value);
}

function assetFieldText(
  asset: Asset | null,
  field: { key: keyof Asset; map?: (value: unknown) => string },
) {
  return assetText(asset, field.key, field.map);
}

function extraFieldText(
  asset: Asset | null,
  field: { key: ExtraKey; map?: (value: unknown) => string },
) {
  return extraText(asset, field.key, field.map);
}

function organizeLabel(id?: string) {
  if (!id) return '-';
  return organizeOptions.value.find(item => item.value === id)?.label || id;
}

function constructionLabel(id?: string) {
  if (!id) return '-';
  return constructionMap.value[id]?.name || constructionOptions.value.find(item => item.value === id)?.label || id;
}

function constructionFieldText(id: string | undefined, key: keyof ConstructionOrg) {
  return textLabel(id ? constructionMap.value[id]?.[key] : undefined);
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
    const bundle = await getPermissionApi();
    organizeOptions.value = (bundle?.organizes ?? []).map((item: any) => ({
      label: item.name || item.organize_name || item.id || item.organize_id,
      value: item.id || item.organize_id,
    })).filter(item => item.label && item.value);
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
  { title: '数据编号', key: 'data_number', width: 130, ellipsis: { tooltip: true } },
  { title: '系统名称', key: 'system_name', width: 160, ellipsis: { tooltip: true },
    render: (row: Asset) => row.system_name || row.name },
  { title: '地址', key: 'address', width: 160, ellipsis: { tooltip: true } },
  { title: '资产所属单位', key: 'organize_id', width: 150, ellipsis: { tooltip: true },
    render: (row: Asset) => organizeLabel(row.organize_id) },
  { title: '系统类型', key: 'system_type', width: 100,
    render: (row: Asset) => systemTypeMap.value[row.system_type ?? ''] || assetTypeLabel(row.type) },
  { title: '保护等级', key: 'security_protection_level', width: 90,
    render: (row: Asset) => row.security_protection_level
      ? h(NTag, { size: 'small', type: 'info' }, () => securityMap.value[row.security_protection_level!] || row.security_protection_level)
      : '-' },
  { title: '生命周期', key: 'lifecycle_state', width: 90,
    render: (row: Asset) => { const m = lifecycleMap[row.lifecycle_state ?? '']; return m ? h(NTag, { size: 'small', type: m.type }, () => m.label) : '-'; } },
  { title: '风险分', key: 'risk_score', width: 70,
    render: (row: Asset) => h('span', { style: { color: (row.risk_score ?? 0) >= 70 ? '#d03050' : (row.risk_score ?? 0) >= 40 ? '#f0a020' : '#18a058' } }, String(row.risk_score ?? 0)) },
  { title: '漏洞', key: 'vuln_count', width: 60,
    render: (row: Asset) => (row.vuln_count ?? 0) > 0
      ? h(NTag, { size: 'small', type: 'error', bordered: false }, () => String(row.vuln_count))
      : h('span', { style: 'color: #ccc' }, '0') },
  { title: '责任人', key: 'responsible_user_name', width: 80 },
  { title: '数据来源', key: 'data_source', width: 80,
    render: (row: Asset) => sourceMap.value[row.data_source ?? ''] || row.data_source || '-' },
  { title: '操作', key: 'actions', width: 230, fixed: 'right' as const,
    render: (row: Asset) => h(NSpace, { size: 4 }, () => [
      h(NPopconfirm, { onPositiveClick: () => onScan(row) }, {
        trigger: () => h(NButton, { size: 'small', type: 'warning' }, () => '扫描'),
        default: () => `对 ${row.address} 发起漏洞扫描？`,
      }),
      h(NButton, { size: 'small', type: 'info', onClick: () => onDetail(row) }, () => '详情'),
      h(NButton, { size: 'small', onClick: () => onEdit(row) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => onDelete(row.id) }, {
        trigger: () => h(NButton, { size: 'small', type: 'error' }, () => '删除'),
        default: () => '确认删除？',
      }),
    ]),
  },
];

async function fetchList() {
  loading.value = true;
  try {
    const params: Record<string, any> = { page: pagination.page, page_size: pagination.pageSize, ...searchForm };
    const res = await getAssetList(params);
    data.value = res.items ?? [];
    pagination.itemCount = res.total ?? 0;
  } catch { message.error('获取资产台账失败'); }
  finally { loading.value = false; }
}

function onSearch() { pagination.page = 1; fetchList(); }
function onReset() {
  Object.assign(searchForm, { keyword: '', data_number: '', system_type: undefined, security_protection_level: undefined, lifecycle_state: undefined, data_source: undefined });
  onSearch();
}

function resetForm() {
  Object.assign(formData, {
    name: '', type: 'server', address: '', port: 0, domain: '', ipv4: '', ipv6: '', url: '', protocol: '',
    service: '', version: '', os: '', data_number: '', system_name: '', system_type: '',
    is_online: true, is_key: false, security_protection_level: '', filing_cert_number: '',
    icp_filing_number: '', organize_id: '', construction_org_id: '', operation_org_id: '', data_source: 'manual_import',
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
    data_number: row.data_number ?? '', system_name: row.system_name ?? '', system_type: row.system_type ?? '',
    is_online: row.is_online ?? true, is_key: row.is_key ?? false,
    security_protection_level: row.security_protection_level ?? '',
    filing_cert_number: row.filing_cert_number ?? '', icp_filing_number: row.icp_filing_number ?? '',
    organize_id: row.organize_id ?? '',
    construction_org_id: row.construction_org_id ?? '', operation_org_id: row.operation_org_id ?? '',
    data_source: row.data_source ?? 'manual_import',
    responsible_user_name: row.responsible_user_name ?? '', remark: row.remark ?? '',
    tags: row.tags ?? [], extra: mergeExtra(row.extra),
  });
  showUnitExtraFields.value = Object.entries(row.extra ?? {}).some(([key, value]) => key in extraDefaults && value !== undefined && value !== null && value !== '');
  await loadAssetDynamicTemplate(row.type || row.system_type);
  await loadAssetDynamicSubmission(row.id);
  setAssetModalVisible(true);
}

const detailVulns = ref<any[]>([]);
const detailMonitorTasks = ref<any[]>([]);

async function onDetail(row: Asset) {
  detailItem.value = row;
  detailVulns.value = [];
  detailMonitorTasks.value = [];
  assetDynamicSubmission.value = null;
  assetDynamicFormData.value = {};
  setDetailVisible(true);
  try {
    detailItem.value = await getAssetDetail(row.id);
  } catch { /* fallback to list row */ }
  await loadAssetDynamicTemplate(detailItem.value?.type || detailItem.value?.system_type);
  await loadAssetDynamicSubmission(row.id);
  try {
    const enrich = await getAssetEnrich(row.id);
    detailVulns.value = enrich?.asset_vulns?.length ? enrich.asset_vulns : enrich?.vulns ?? [];
    detailMonitorTasks.value = enrich?.monitor_tasks ?? [];
  } catch { /* detail enrichment is non-critical */ }
}

async function onSaveWithDynamicForm() {
  if (!formData.name || !formData.address) {
    message.warning('请填写名称和地址');
    return;
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
      name: `扫描-${row.system_name || row.name}`,
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
  { label: '生命周期', value: 'lifecycle_state' },
  { label: '数据来源', value: 'data_source' },
  { label: '责任人', value: 'responsible_user_name' },
  { label: '状态(1活跃/0不活跃)', value: 'status' },
  { label: '是否关键资产', value: 'is_key' },
  { label: '备注', value: 'remark' },
];
const batchEditValueOptions = computed<Record<string, DictOption[]>>(() => ({
  system_type: systemTypeOptions.value,
  security_protection_level: securityOptions.value,
  lifecycle_state: lifecycleOptions,
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
    if (searchForm.system_type) params.system_type = searchForm.system_type;
    if (searchForm.security_protection_level) params.security_protection_level = searchForm.security_protection_level;
    if (searchForm.lifecycle_state) params.lifecycle_state = searchForm.lifecycle_state;
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

onMounted(() => {
  fetchList();
  loadReferenceOptions();
  loadDictOptions();
});
</script>

<template>
  <div style="padding: 16px">
    <NCard title="资产台账" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NButton type="primary" size="small" @click="onAdd">登记资产</NButton>
          <NButton size="small" @click="setImportVisible(true)">导入</NButton>
          <NButton size="small" :loading="exportLoading" @click="onExport">导出</NButton>
          <NButton size="small" :disabled="!checkedKeys.length" @click="openBatchEdit">
            批量编辑{{ checkedKeys.length ? ` (${checkedKeys.length})` : '' }}
          </NButton>
          <NPopconfirm @positive-click="onBatchScan">
            <template #trigger><NButton type="warning" size="small" :disabled="!checkedKeys.length">批量扫描</NButton></template>
            对选中的资产发起漏洞扫描？
          </NPopconfirm>
          <NButton type="info" size="small" :loading="sendingToMonitor" :disabled="!checkedKeys.length" @click="onSendToMonitor">
            发送监控{{ checkedKeys.length ? ` (${checkedKeys.length})` : '' }}
          </NButton>
          <NButton type="primary" size="small" secondary :loading="submittingToVerify" :disabled="!checkedKeys.length" @click="onSubmitToVerify">
            提交核验{{ checkedKeys.length ? ` (${checkedKeys.length})` : '' }}
          </NButton>
          <NPopconfirm @positive-click="onBatchDelete">
            <template #trigger><NButton type="error" size="small" :disabled="!checkedKeys.length">批量删除</NButton></template>
            确认删除选中的资产？
          </NPopconfirm>
        </NSpace>
      </template>

      <NForm inline label-placement="left" :show-feedback="false" style="margin-bottom: 16px">
        <NFormItem label="关键词"><NInput v-model:value="searchForm.keyword" placeholder="名称/地址" clearable style="width: 160px" /></NFormItem>
        <NFormItem label="编号"><NInput v-model:value="searchForm.data_number" placeholder="数据编号" clearable style="width: 130px" /></NFormItem>
        <NFormItem label="类型"><NSelect v-model:value="searchForm.system_type" :options="systemTypeOptions" placeholder="全部" clearable style="width: 110px" /></NFormItem>
        <NFormItem label="等保"><NSelect v-model:value="searchForm.security_protection_level" :options="securityOptions" placeholder="全部" clearable style="width: 90px" /></NFormItem>
        <NFormItem label="状态"><NSelect v-model:value="searchForm.lifecycle_state" :options="lifecycleOptions" placeholder="全部" clearable style="width: 100px" /></NFormItem>
        <NFormItem><NSpace :size="8"><NButton type="primary" @click="onSearch">查询</NButton><NButton @click="onReset">重置</NButton></NSpace></NFormItem>
      </NForm>

      <NDataTable v-model:checked-row-keys="checkedKeys" :columns="columns" :data="data" :loading="loading"
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
          <NGridItem><NFormItem label="资产名称" required><NInput v-model:value="formData.name" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="系统名称"><NInput v-model:value="formData.system_name" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="地址" required><NInput v-model:value="formData.address" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="端口"><NInputNumber v-model:value="formData.port" :min="0" :max="65535" style="width: 100%" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="域名"><NInput v-model:value="formData.domain" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="IPv4地址"><NInput v-model:value="formData.ipv4" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="IPv6地址"><NInput v-model:value="formData.ipv6" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="网址"><NInput v-model:value="formData.url" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="协议"><NInput v-model:value="formData.protocol" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="系统类型"><NSelect v-model:value="formData.system_type" :options="systemTypeOptions" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="资产类型"><NSelect v-model:value="formData.type" :options="assetTypeOptions" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="数据编号"><NInput v-model:value="formData.data_number" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="安全保护等级"><NSelect v-model:value="formData.security_protection_level" :options="securityOptions" clearable /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="是否联网"><NSwitch v-model:value="formData.is_online" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="关键信息基础设施"><NSwitch v-model:value="formData.is_key" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="备案证明编号"><NInput v-model:value="formData.filing_cert_number" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="ICP备案号"><NInput v-model:value="formData.icp_filing_number" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="所属单位"><NSelect v-model:value="formData.organize_id" :options="organizeOptions" filterable clearable /></NFormItem></NGridItem>
          <NGridItem>
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
          <NGridItem>
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
          <NGridItem><NFormItem label="责任人"><NInput v-model:value="formData.responsible_user_name" /></NFormItem></NGridItem>
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

    <!-- 详情抽屉 -->
    <NDrawer v-model:show="showDetail" :width="720" @update:show="setDetailVisible">
      <NDrawerContent :title="detailItem?.system_name || detailItem?.name || '资产详情'">
        <NTabs v-if="detailItem" type="line" size="small">
          <NTabPane name="info" tab="资产信息">
            <NDescriptions class="asset-detail-section" label-placement="left" bordered :column="1" size="small">
              <NDescriptionsItem label="ID">{{ detailItem.id }}</NDescriptionsItem>
              <NDescriptionsItem label="名称">{{ detailItem.name }}</NDescriptionsItem>
              <NDescriptionsItem label="地址">{{ detailItem.address }}</NDescriptionsItem>
              <NDescriptionsItem label="域名">{{ detailItem.domain || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="端口">{{ detailItem.port || '-' }}</NDescriptionsItem>
              <NDescriptionsItem
                v-for="field in assetInfoFields"
                :key="field.key"
                :label="field.label"
              >
                {{ assetFieldText(detailItem, field) }}
              </NDescriptionsItem>
              <NDescriptionsItem label="数据编号">{{ detailItem.data_number || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="所属单位">{{ organizeLabel(detailItem.organize_id) }}</NDescriptionsItem>
              <NDescriptionsItem label="建设单位">{{ constructionLabel(detailItem.construction_org_id) }}</NDescriptionsItem>
              <NDescriptionsItem label="运维单位">{{ constructionLabel(detailItem.operation_org_id) }}</NDescriptionsItem>
              <NDescriptionsItem label="生命周期">{{ lifecycleMap[detailItem.lifecycle_state ?? '']?.label || detailItem.lifecycle_state || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="风险分">{{ detailItem.risk_score ?? 0 }}</NDescriptionsItem>
              <NDescriptionsItem label="漏洞数">{{ detailItem.vuln_count ?? 0 }}</NDescriptionsItem>
              <NDescriptionsItem label="责任人">{{ detailItem.responsible_user_name || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="数据来源">{{ sourceMap[detailItem.data_source ?? ''] || detailItem.data_source || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="等保证号">{{ detailItem.filing_cert_number || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="ICP备案">{{ detailItem.icp_filing_number || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="最近扫描">{{ detailItem.last_scan_at || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="SSL到期">{{ detailItem.ssl_expires_at || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="创建时间">{{ detailItem.created_at }}</NDescriptionsItem>
              <NDescriptionsItem label="备注">{{ detailItem.remark || '-' }}</NDescriptionsItem>
            </NDescriptions>
          </NTabPane>
          <NTabPane name="unit" tab="单位信息">
            <NDescriptions label-placement="left" bordered :column="1" size="small">
              <NDescriptionsItem label="所属单位">{{ organizeLabel(detailItem.organize_id) }}</NDescriptionsItem>
              <NDescriptionsItem
                v-for="field in unitInfoFields"
                :key="field.key"
                :label="field.label"
              >
                {{ extraFieldText(detailItem, field) }}
              </NDescriptionsItem>
            </NDescriptions>
          </NTabPane>
          <NTabPane name="construction" tab="建设单位">
            <NDescriptions label-placement="left" bordered :column="1" size="small">
              <NDescriptionsItem label="公网安备案号">{{ constructionFieldText(detailItem.construction_org_id, 'security_filing') }}</NDescriptionsItem>
              <NDescriptionsItem label="建设单位名称">{{ constructionLabel(detailItem.construction_org_id) }}</NDescriptionsItem>
              <NDescriptionsItem label="系统建设单位所在地">{{ constructionFieldText(detailItem.construction_org_id, 'location') }}</NDescriptionsItem>
              <NDescriptionsItem label="系统建设单位详细地址">{{ constructionFieldText(detailItem.construction_org_id, 'address') }}</NDescriptionsItem>
              <NDescriptionsItem label="系统建设负责人及职务">{{ constructionFieldText(detailItem.construction_org_id, 'charge_person') }}</NDescriptionsItem>
              <NDescriptionsItem label="系统建设联系电话">{{ constructionFieldText(detailItem.construction_org_id, 'charge_phone') }}</NDescriptionsItem>
            </NDescriptions>
          </NTabPane>
          <NTabPane name="operation" tab="运维单位">
            <NDescriptions label-placement="left" bordered :column="1" size="small">
              <NDescriptionsItem label="运维单位名称">{{ constructionLabel(detailItem.operation_org_id) }}</NDescriptionsItem>
              <NDescriptionsItem label="系统运维负责人及职务">{{ constructionFieldText(detailItem.operation_org_id, 'charge_person') }}</NDescriptionsItem>
              <NDescriptionsItem label="系统运维联系电话">{{ constructionFieldText(detailItem.operation_org_id, 'charge_phone') }}</NDescriptionsItem>
              <NDescriptionsItem label="系统建设单位所在地">{{ constructionFieldText(detailItem.operation_org_id, 'location') }}</NDescriptionsItem>
              <NDescriptionsItem label="系统建设单位详细地址">{{ constructionFieldText(detailItem.operation_org_id, 'address') }}</NDescriptionsItem>
            </NDescriptions>
          </NTabPane>
          <NTabPane v-if="assetDynamicTemplate || assetDynamicSubmission?.version" name="dynamic" tab="扩展信息">
            <NCard :bordered="false" size="small" :loading="assetDynamicLoading">
              <div v-if="assetDynamicSubmission?.version" class="asset-dynamic-note">
                该扩展信息按填写时的 v{{ assetDynamicSubmission.version.version }} 表单快照渲染。
              </div>
              <DynamicFormRenderer
                v-if="assetDynamicTemplate || assetDynamicSubmission?.version"
                v-model="assetDynamicFormData"
                readonly
                :schema="assetDynamicSubmission?.version?.schema || assetDynamicTemplate?.schema || {}"
                :options="assetDynamicRenderOptions"
              />
              <div v-else class="asset-empty-dynamic">暂无扩展表单数据</div>
            </NCard>
          </NTabPane>
          <NTabPane name="vulns" tab="关联漏洞">
            <div v-if="detailVulns.length === 0" style="padding: 20px; text-align: center; color: #999">暂无关联漏洞</div>
            <NDataTable v-else :data="detailVulns" :bordered="false" size="small" :columns="[
              { title: '漏洞', key: 'title', ellipsis: { tooltip: true } },
              { title: '严重度', key: 'severity', width: 70 },
              { title: '状态', key: 'status', width: 70 },
              { title: '时间', key: 'created_at', width: 150 },
            ]" :max-height="400" />
            <NButton v-if="detailVulns.length > 0" text type="info" style="margin-top: 8px" @click="router.push(`/scan/vulns?asset_id=${detailItem.id}`)">查看全部漏洞 →</NButton>
          </NTabPane>
          <NTabPane name="monitor" tab="关联监控">
            <div v-if="detailMonitorTasks.length === 0" style="padding: 20px; text-align: center; color: #999">暂无关联监控任务</div>
            <NDataTable v-else :data="detailMonitorTasks" :bordered="false" size="small" :columns="[
              { title: '任务名', key: 'task_name', ellipsis: { tooltip: true } },
              { title: '首页', key: 'target_homepage', width: 180, ellipsis: { tooltip: true } },
              { title: '状态', key: 'enabled', width: 60, render: (row: any) => row.enabled ? '启用' : '停用' },
            ]" :max-height="400" />
            <NButton v-if="detailMonitorTasks.length > 0" text type="info" style="margin-top: 8px" @click="router.push('/monitor/tasks')">查看监控任务 →</NButton>
          </NTabPane>
        </NTabs>
      </NDrawerContent>
    </NDrawer>

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
</template>

<style scoped>
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
</style>
