import type { PaginationProps, TreeOption, UploadFileInfo } from 'naive-ui';

import { computed, nextTick, reactive, ref, watch } from 'vue';
import { useMessage } from 'naive-ui';

import {
  createAsset,
  deleteAsset,
  getAssetList,
  getAssetRegionScope,
  getAssetStats,
  downloadImportTemplate,
  importAssets,
  updateAsset,
  type Asset,
} from '#/api/asset';
import {
  getImportErrorPayload,
  getRequestErrorMessage,
  type ImportFailedRowPayload,
  type ImportIssuePayload,
} from '#/api/helpers';
import { buildImportErrorTableRows, importErrorSummary } from '../import-errors';
import {
  createConstruction,
  createOrganize,
  createVerifyTasks,
  getConstructionList,
  getOrganizeDetail,
  getOrganizeList,
  getOrganizeTree,
  updateOrganize,
  type ConstructionOrg,
  type Organize,
} from '#/api/assetmgr';
import { dictItemsToOptions, getSystemDictItems } from '#/api/system/dict';
import { createTask, getScanEnginePresets, type ScanEnginePreset } from '#/api/task';
import { getTemplateList, type ScanTemplate } from '#/api/template';
import {
  getDynamicFormSubmission,
  getDynamicFormSubmissions,
  getDynamicFormTemplates,
  normalizePagedResponse,
  saveDynamicFormSubmission,
  type DynamicFormSubmissionDetail,
  type DynamicFormTemplate,
} from '#/api/formdesign';
import {
  deriveAssetNetworkFieldsFromAccessAddress,
  mergeDerivedNetworkFields,
  normalizeAssetAccessAddress,
  validateAssetAccessAddress,
} from '#/utils/asset-address';
import { regionLabelFromCode } from '#/utils/region';
import {
  validateCNPhone,
  validateIPv4List,
  validatePort,
  validateUnitProfile,
  validateUSCC,
} from '#/utils/validators';

import {
  BOOLEAN_FILTER_OPTIONS,
  DEFAULT_ASSET_FAMILY_OPTIONS,
  DEFAULT_INDUSTRY_CATEGORY_OPTIONS,
  DEFAULT_SOURCE_OPTIONS,
  DEFAULT_UNIT_TYPE_OPTIONS,
  EMPTY_LEDGER_EXTRA,
  EMPTY_LEDGER_FORM,
  EMPTY_LEDGER_STATS,
  EMPTY_QUICK_CONSTRUCTION_FORM,
  EMPTY_QUICK_ORGANIZE_FORM,
  EMPTY_SCAN_FORM,
  EMPTY_VERIFY_FORM,
  VERIFY_SOURCE_OPTIONS,
} from '../constants';
import { appendExecutorNodeParams, useScanExecutorNodes } from '../../../scan/scan-executor';
import {
  assetTarget,
  buildScanAssetParameters,
  buildScanTaskName,
  resolveScanTemplate as resolveScanTemplateForAssets,
} from '../scan-utils';
import type {
  LedgerConstructionForm,
  LedgerFormModel,
  LedgerOption,
  LedgerScanForm,
  LedgerScopeDimension,
  LedgerSearchForm,
  LedgerStats,
  LedgerVerifyForm,
} from '../types';
import { runAssetOnlineSync } from '../../composables/use-asset-online-sync';
import { downloadBlob } from '../file-utils';
import {
  appendFallbackOption,
  assetIdentifier,
  buildDictTreeOptions,
  buildOrgTreeOptions,
  buildOrganizeSearchTreeOptions,
  buildRegionTreeFromAssetCodes,
  flattenOrgTree,
  regionAssetQueryFromCode,
  regionScopeLabelFromCode,
  mapOrganizeToUnitExtra,
  mapUnitExtraToOrganizeUpdate,
  optionLabelOf,
  resolveLedgerFormAddress,
  stripUnitProfileFromExtra,
} from '../utils';
import { useLedgerBatchEdit } from './use-ledger-batch-edit';
import { useLedgerSideActions } from './use-ledger-side-actions';

function normalizeConstructionListResponse(res: any): ConstructionOrg[] {
  const body = res?.data ?? res;
  return body?.data ?? body?.items ?? [];
}

export function useLedgerPage() {
  const message = useMessage();
  const loading = ref(false);
  const treeLoading = ref(false);
  const saving = ref(false);
  const importLoading = ref(false);
  const templateDownloading = ref(false);
  const quickConstructionLoading = ref(false);
  const quickOrganizeLoading = ref(false);
  const creatingScanTask = ref(false);
  const submittingVerify = ref(false);
  const rows = ref<Asset[]>([]);
  const checkedRowKeys = ref<string[]>([]);
  const assetFamilyOptions = ref<LedgerOption[]>([...DEFAULT_ASSET_FAMILY_OPTIONS]);
  const sourceOptions = ref<LedgerOption[]>([...DEFAULT_SOURCE_OPTIONS]);
  const securityOptions = ref<LedgerOption[]>([]);
  const unitTypeOptions = ref<LedgerOption[]>([...DEFAULT_UNIT_TYPE_OPTIONS]);
  const industryCategoryOptions = ref<LedgerOption[]>([...DEFAULT_INDUSTRY_CATEGORY_OPTIONS]);
  const constructionOptions = ref<LedgerOption[]>([]);
  const orgTreeOptions = ref<TreeOption[]>([]);
  const orgTreeSearchOptions = ref<TreeOption[]>([]);
  const orgSearchKeyword = ref('');
  const orgNameMap = ref<Record<string, string>>({});
  const orgParentMap = ref<Record<string, string>>({});
  const scopeDimension = ref<LedgerScopeDimension>('organize');
  const selectedOrgKey = ref<string | null>(null);
  const selectedRegionKey = ref<string | null>(null);
  const selectedIndustryKey = ref<string | null>(null);
  const selectedAssetFamilyKey = ref<string | null>(null);
  const templates = ref<ScanTemplate[]>([]);
  const enginePresets = ref<ScanEnginePreset[]>([]);
  const moduleConfigs = ref<Record<string, Record<string, any>>>({});
  const scanAssets = ref<Asset[]>([]);
  const assetDynamicTemplate = ref<DynamicFormTemplate | null>(null);
  const assetDynamicSubmission = ref<DynamicFormSubmissionDetail | null>(null);
  const assetDynamicFormData = ref<Record<string, any>>({});
  const assetDynamicLoading = ref(false);
  const activeFamily = ref('all');
  const stats = reactive<LedgerStats>(EMPTY_LEDGER_STATS());
  const searchForm = reactive<LedgerSearchForm>({
    keyword: '',
    assetFamily: undefined,
    securityLevel: undefined,
    dataSource: undefined,
    riskScoreMin: null,
    riskScoreMax: null,
    isKey: '',
  });
  const formModel = reactive<LedgerFormModel>(EMPTY_LEDGER_FORM());
  const quickConstructionForm = reactive<LedgerConstructionForm>(EMPTY_QUICK_CONSTRUCTION_FORM());
  const quickOrganizeForm = reactive(EMPTY_QUICK_ORGANIZE_FORM());
  const scanForm = reactive<LedgerScanForm>(EMPTY_SCAN_FORM());
  const scanExecutor = useScanExecutorNodes();
  const verifyForm = reactive<LedgerVerifyForm>(EMPTY_VERIFY_FORM());
  const showEditModal = ref(false);
  const showImportModal = ref(false);
  const importErrorMessage = ref('');
  const importErrorIssues = ref<ImportIssuePayload[]>([]);
  const importErrorCount = ref(0);
  const importErrorFailedRows = ref<ImportFailedRowPayload[]>([]);
  const showScanModal = ref(false);
  const showVerifyModal = ref(false);
  const showQuickConstructionModal = ref(false);
  const showQuickOrganizeModal = ref(false);
  const showScanAdvanced = ref(false);
  const showScanModuleConfig = ref(false);
  const showAdvancedFilter = ref(false);
  const editingId = ref<string | null>(null);
  const importFile = ref<File | null>(null);
  const skipOrganizeExtraFill = ref(false);
  let organizeExtraFillSeq = 0;

  const isEditing = computed(() => !!editingId.value);
  const regionScopeItems = ref<Array<{ count: number; region_code: string }>>([]);
  const regionTreeOptions = computed(() => buildRegionTreeFromAssetCodes(regionScopeItems.value));
  const industryTreeOptions = computed(() => buildDictTreeOptions(industryCategoryOptions.value));
  const assetFamilyScopeTreeOptions = computed(() => buildDictTreeOptions(assetFamilyOptions.value));
  const scopeLabel = computed(() => {
    switch (scopeDimension.value) {
      case 'organize':
        return selectedOrgKey.value
          ? orgNameMap.value[selectedOrgKey.value] ?? selectedOrgKey.value
          : '';
      case 'region':
        return selectedRegionKey.value
          ? regionScopeLabelFromCode(selectedRegionKey.value)
          : '';
      case 'industry':
        return selectedIndustryKey.value
          ? optionLabelOf(industryCategoryOptions.value, selectedIndustryKey.value)
          : '';
      case 'asset_family':
        return selectedAssetFamilyKey.value
          ? optionLabelOf(assetFamilyOptions.value, selectedAssetFamilyKey.value)
          : '';
      default:
        return '';
    }
  });
  const orgTreeDisplay = computed(() =>
    orgSearchKeyword.value.trim() ? orgTreeSearchOptions.value : orgTreeOptions.value,
  );
  const orgTreeSearchMode = computed(() => !!orgSearchKeyword.value.trim());
  const scopeUsesAssetFamily = computed(() => scopeDimension.value === 'asset_family');
  const selectedAssets = computed(() => {
    const selected = new Set(checkedRowKeys.value);
    return rows.value.filter((row) => selected.has(row.id));
  });
  const templateOptions = computed(() =>
    templates.value.map((item) => ({
      label: `${item.name}${item.builtin ? '（内置）' : ''}`,
      value: item.id,
    })),
  );
  const enginePresetOptions = computed<LedgerOption[]>(() => [
    { label: '不使用预设', value: '' },
    ...enginePresets.value.map((p) => ({
      label: `${p.name} — ${p.description}`,
      value: p.name,
    })),
  ]);
  const familyFilterOptions = computed<readonly LedgerOption[]>(() => [
    { label: '全部', value: 'all' },
    ...assetFamilyOptions.value,
  ]);

  const pagination = reactive<PaginationProps>({
    page: 1,
    pageSize: 20,
    itemCount: 0,
    showSizePicker: true,
    pageSizes: [10, 20, 50, 100],
    onChange: (page) => {
      pagination.page = page;
      void fetchList();
    },
    onUpdatePageSize: (pageSize) => {
      pagination.page = 1;
      pagination.pageSize = pageSize;
      void fetchList();
    },
  });

  function resetForm() {
    Object.assign(formModel, EMPTY_LEDGER_FORM(), {
      assetFamily: assetFamilyOptions.value[0]?.value ?? 'ip',
      dataSource: sourceOptions.value[0]?.value ?? 'manual_import',
      extra: EMPTY_LEDGER_EXTRA(),
    });
    editingId.value = null;
  }

  function resetQuickConstructionForm() {
    Object.assign(quickConstructionForm, EMPTY_QUICK_CONSTRUCTION_FORM());
  }

  function resetQuickOrganizeForm() {
    Object.assign(quickOrganizeForm, EMPTY_QUICK_ORGANIZE_FORM());
  }

  function resetScanForm() {
    Object.assign(scanForm, EMPTY_SCAN_FORM());
    moduleConfigs.value = {};
    scanAssets.value = [];
    showScanAdvanced.value = false;
  }

  function resetVerifyForm() {
    Object.assign(verifyForm, EMPTY_VERIFY_FORM());
  }

  function resetAssetDynamicForm() {
    assetDynamicTemplate.value = null;
    assetDynamicSubmission.value = null;
    assetDynamicFormData.value = {};
  }

  async function loadAssetDynamicTemplate(objectType?: string) {
    assetDynamicLoading.value = true;
    try {
      const params = {
        business: 'asset',
        enabled: 'true',
        object_type: objectType || undefined,
        page: 1,
        page_size: 100,
      };
      let items = normalizePagedResponse<DynamicFormTemplate>(await getDynamicFormTemplates(params)).items;
      if (objectType && items.length === 0) {
        items = normalizePagedResponse<DynamicFormTemplate>(await getDynamicFormTemplates({
          business: 'asset',
          enabled: 'true',
          page: 1,
          page_size: 100,
        })).items;
      }
      assetDynamicTemplate.value = items.find((item) => item.is_default) || items[0] || null;
    } catch {
      assetDynamicTemplate.value = null;
    } finally {
      assetDynamicLoading.value = false;
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
      assetDynamicFormData.value = { ...(detail.submission?.form_data ?? {}) };
    } catch {
      assetDynamicSubmission.value = null;
      assetDynamicFormData.value = {};
    } finally {
      assetDynamicLoading.value = false;
    }
  }

  async function saveAssetDynamicForm(assetId: string, objectType?: string) {
    if (!assetDynamicTemplate.value) return;
    await saveDynamicFormSubmission({
      business: 'asset',
      form_data: assetDynamicFormData.value,
      object_id: assetId,
      object_type: objectType || 'asset',
      template_id: assetDynamicTemplate.value.id,
      template_version_id:
        assetDynamicSubmission.value?.submission?.template_version_id
        || assetDynamicSubmission.value?.version?.id
        || assetDynamicTemplate.value.current_version_id,
    });
  }

  function updateAssetDynamicFormData(value: Record<string, any>) {
    assetDynamicFormData.value = { ...value };
  }

  async function loadDictOptions(dictCode: string, fallback: LedgerOption[] = [], extraOption?: LedgerOption) {
    try {
      const options = dictItemsToOptions(await getSystemDictItems(dictCode, true));
      return extraOption ? appendFallbackOption(options, extraOption) : options;
    } catch {
      return extraOption ? appendFallbackOption([...fallback], extraOption) : [...fallback];
    }
  }

  async function loadOptions() {
    [
      assetFamilyOptions.value,
      sourceOptions.value,
      securityOptions.value,
      unitTypeOptions.value,
      industryCategoryOptions.value,
    ] = await Promise.all([
      loadDictOptions('asset_family', DEFAULT_ASSET_FAMILY_OPTIONS, { label: '其他', value: 'other' }),
      loadDictOptions('asset_data_source', DEFAULT_SOURCE_OPTIONS, { label: '其他', value: 'other' }),
      loadDictOptions('asset_security_level'),
      loadDictOptions('organize_unit_type', DEFAULT_UNIT_TYPE_OPTIONS, { label: '其他', value: '其他' }),
      loadDictOptions('organize_industry_category', DEFAULT_INDUSTRY_CATEGORY_OPTIONS, { label: '其他', value: '其他' }),
    ]);
  }

  async function loadRegionScope() {
    try {
      regionScopeItems.value = await getAssetRegionScope();
    } catch {
      regionScopeItems.value = [];
    }
  }

  async function loadOrgTree() {
    treeLoading.value = true;
    try {
      const tree = await getOrganizeTree();
      const options = buildOrgTreeOptions(Array.isArray(tree) ? tree : []);
      orgTreeOptions.value = options;
      const nameMap: Record<string, string> = {};
      const parentMap: Record<string, string> = {};
      flattenOrgTree(options, nameMap, parentMap);
      orgNameMap.value = nameMap;
      orgParentMap.value = parentMap;
    } catch {
      orgTreeOptions.value = [];
      orgNameMap.value = {};
      orgParentMap.value = {};
    } finally {
      treeLoading.value = false;
    }
  }

  async function searchOrganizes(keyword: string) {
    const q = keyword.trim();
    orgSearchKeyword.value = q;
    if (!q) {
      orgTreeSearchOptions.value = [];
      return;
    }
    treeLoading.value = true;
    try {
      const res = await getOrganizeList({ page: 1, page_size: 200, name: q });
      const body = (res as any)?.data ?? res;
      const items = (body?.data ?? body?.items ?? []) as Organize[];
      const nameMap = { ...orgNameMap.value };
      items.forEach((item) => {
        if (item.id) nameMap[item.id] = item.name || nameMap[item.id] || item.id;
      });
      orgTreeSearchOptions.value = buildOrganizeSearchTreeOptions(
        items,
        nameMap,
        orgParentMap.value,
      );
    } catch {
      orgTreeSearchOptions.value = [];
    } finally {
      treeLoading.value = false;
    }
  }

  async function loadConstructionOptions() {
    try {
      const res = await getConstructionList({ page: 1, page_size: 200 });
      constructionOptions.value = normalizeConstructionListResponse(res).map((item) => ({
        label: item.name,
        value: item.id,
      }));
    } catch {
      constructionOptions.value = [];
    }
  }

  async function loadTemplates() {
    try {
      const res = await getTemplateList({ page: 1, page_size: 100 });
      templates.value = (res.items ?? []).filter((item) => item.enabled);
    } catch {
      templates.value = [];
    }
  }

  async function loadEnginePresets() {
    try {
      enginePresets.value = await getScanEnginePresets();
    } catch {
      enginePresets.value = [];
    }
  }

  function clearScopeSelection() {
    selectedOrgKey.value = null;
    selectedRegionKey.value = null;
    selectedIndustryKey.value = null;
    selectedAssetFamilyKey.value = null;
    orgSearchKeyword.value = '';
    orgTreeSearchOptions.value = [];
  }

  function setScopeDimension(dim: LedgerScopeDimension) {
    if (scopeDimension.value === dim) return;
    scopeDimension.value = dim;
    clearScopeSelection();
    if (dim === 'asset_family') {
      activeFamily.value = 'all';
      searchForm.assetFamily = undefined;
    }
    pagination.page = 1;
    void reload();
  }

  function resetScopePanel() {
    clearScopeSelection();
    pagination.page = 1;
    void reload();
  }

  function buildQueryParams() {
    const regionQuery =
      scopeDimension.value === 'region' && selectedRegionKey.value
        ? regionAssetQueryFromCode(selectedRegionKey.value)
        : {};
    return {
      page: pagination.page,
      page_size: pagination.pageSize,
      keyword: searchForm.keyword || undefined,
      organize_id:
        scopeDimension.value === 'organize' && selectedOrgKey.value
          ? selectedOrgKey.value
          : undefined,
      ...regionQuery,
      industry_category:
        scopeDimension.value === 'industry' && selectedIndustryKey.value
          ? selectedIndustryKey.value
          : undefined,
      asset_family:
        scopeDimension.value === 'asset_family' && selectedAssetFamilyKey.value
          ? selectedAssetFamilyKey.value
          : searchForm.assetFamily || undefined,
      security_protection_level: searchForm.securityLevel || undefined,
      data_source: searchForm.dataSource || undefined,
      risk_score_min: searchForm.riskScoreMin ?? undefined,
      risk_score_max: searchForm.riskScoreMax ?? undefined,
      is_key: searchForm.isKey || undefined,
    };
  }

  async function fetchStats() {
    try {
      const params = buildQueryParams();
      delete (params as any).page;
      delete (params as any).page_size;
      const res = await getAssetStats(params);
      stats.total = Number(res?.total ?? 0);
      stats.active = Number(res?.active ?? 0);
      stats.keyAssets = Number(res?.key_assets ?? 0);
      stats.riskHigh = Number(res?.risk_high ?? 0);
      stats.withVulns = Number(res?.with_vulns ?? 0);
    } catch {
      Object.assign(stats, EMPTY_LEDGER_STATS());
    }
  }

  async function fetchList() {
    loading.value = true;
    try {
      const res = await getAssetList(buildQueryParams());
      rows.value = res.items ?? [];
      pagination.itemCount = Number(res.total ?? 0);
      checkedRowKeys.value = checkedRowKeys.value.filter((key) => rows.value.some((row) => row.id === key));
    } finally {
      loading.value = false;
    }
  }

  async function reload() {
    await Promise.all([fetchStats(), fetchList()]);
  }

  function handleSearch() {
    pagination.page = 1;
    void reload();
  }

  function handleResetSearch() {
    searchForm.keyword = '';
    searchForm.assetFamily = undefined;
    searchForm.securityLevel = undefined;
    searchForm.dataSource = undefined;
    searchForm.riskScoreMin = null;
    searchForm.riskScoreMax = null;
    searchForm.isKey = '';
    activeFamily.value = 'all';
    clearScopeSelection();
    pagination.page = 1;
    void reload();
  }

  function changeFamily(value: string) {
    activeFamily.value = value;
    searchForm.assetFamily = value === 'all' ? undefined : value;
    pagination.page = 1;
    void reload();
  }

  function selectOrg(key: string | null) {
    selectedOrgKey.value = key;
    pagination.page = 1;
    void reload();
  }

  function selectRegion(key: string | null) {
    selectedRegionKey.value = key;
    pagination.page = 1;
    void reload();
  }

  function selectIndustry(key: string | null) {
    selectedIndustryKey.value = key;
    pagination.page = 1;
    void reload();
  }

  function selectAssetFamily(key: string | null) {
    selectedAssetFamilyKey.value = key;
    pagination.page = 1;
    void reload();
  }

  function handleCheckedRowKeys(keys: string[]) {
    checkedRowKeys.value = keys;
  }

  async function openCreateModal() {
    resetForm();
    resetAssetDynamicForm();
    await loadAssetDynamicTemplate(formModel.assetFamily);
    showEditModal.value = true;
  }

  async function syncOrganizeFromUnitExtra(organizeId: string) {
    await updateOrganize(organizeId, mapUnitExtraToOrganizeUpdate(formModel.extra));
  }

  async function applyOrganizeToUnitExtra(organizeId: string) {
    if (!organizeId) return;
    const seq = ++organizeExtraFillSeq;
    try {
      const org = (await getOrganizeDetail(organizeId)) as Organize;
      if (seq !== organizeExtraFillSeq) return;
      Object.assign(formModel.extra, mapOrganizeToUnitExtra(org));
    } catch {
      if (seq === organizeExtraFillSeq) {
        message.warning('未能加载单位档案，请手动填写单位信息');
      }
    }
  }

  watch(
    () => formModel.organizeId,
    (organizeId, prev) => {
      if (skipOrganizeExtraFill.value || !organizeId || organizeId === prev) return;
      void applyOrganizeToUnitExtra(organizeId);
    },
  );

  async function openEditModal(row: Asset) {
    skipOrganizeExtraFill.value = true;
    editingId.value = row.id;
    Object.assign(formModel, {
      name: row.name ?? '',
      assetFamily: row.asset_family ?? assetFamilyOptions.value[0]?.value ?? 'ip',
      organizeId: row.organize_id ?? '',
      dataNumber: row.data_number ?? '',
      address: resolveLedgerFormAddress(row),
      ipv4: row.ipv4 ?? '',
      ipv6: row.ipv6 ?? '',
      port: row.port ?? null,
      isOnline: row.is_online ?? true,
      isKey: row.is_key ?? false,
      responsibleUserName: row.responsible_user_name ?? '',
      dataSource: row.data_source ?? sourceOptions.value[0]?.value ?? 'manual_import',
      securityProtectionLevel: row.security_protection_level ?? '',
      filingCertNumber: row.filing_cert_number ?? '',
      icpFilingNumber: row.icp_filing_number ?? '',
      publicSecurityFiling: row.public_security_filing ?? '',
      operationOrgId: row.operation_org_id ?? '',
      remark: row.remark ?? '',
      extra: { ...EMPTY_LEDGER_EXTRA() },
    });
    resetAssetDynamicForm();
    await loadAssetDynamicTemplate(formModel.assetFamily);
    await loadAssetDynamicSubmission(row.id);
    showEditModal.value = true;
    await nextTick();
    skipOrganizeExtraFill.value = false;
    if (formModel.organizeId) {
      await applyOrganizeToUnitExtra(formModel.organizeId);
    }
  }

  /** 以域名/站点为主的分类：访问地址为主要目标，不要求 IPv4 */
  const FAMILY_URL_FIRST = new Set(['domain_site', 'official_account', 'mini_program']);

  function resolvedAssetAddress() {
    return formModel.address.trim() || formModel.ipv4.trim();
  }

  async function submitForm() {
    if (!formModel.name.trim()) return message.warning('请输入系统名称');
    if (!formModel.organizeId) return message.warning('请选择所属单位');
    if (!formModel.assetFamily) return message.warning('请选择资产分类');
    const fam = formModel.assetFamily || '';
    if (FAMILY_URL_FIRST.has(fam)) {
      if (!formModel.address.trim()) return message.warning('请填写访问地址');
    } else if (!formModel.address.trim() && !formModel.ipv4.trim()) {
      return message.warning('请填写访问地址或 IPv4（至少一项）');
    }

    const ipv4Err = validateIPv4List(formModel.ipv4);
    if (ipv4Err) return message.warning(ipv4Err);
    const portErr = validatePort(formModel.port);
    if (portErr) return message.warning(portErr);
    const unitErr = validateUnitProfile(formModel.extra);
    if (unitErr) return message.warning(unitErr);

    if (formModel.address.trim()) {
      const addressErr = validateAssetAccessAddress(formModel.address, {
        allowEmpty: true,
        assetFamily: fam,
      });
      if (addressErr) return message.warning(addressErr);
      formModel.address = normalizeAssetAccessAddress(formModel.address, {
        assetFamily: fam,
      });
    }

    const address = resolvedAssetAddress();
    const derivedNetwork = address
      ? deriveAssetNetworkFieldsFromAccessAddress(address, { assetFamily: fam })
      : null;

    saving.value = true;
    try {
      try {
        await syncOrganizeFromUnitExtra(formModel.organizeId);
      } catch (error) {
        message.error(
          getRequestErrorMessage(error, '单位信息同步到所属单位失败，请检查后重试'),
        );
        return;
      }

      const extraPayload = stripUnitProfileFromExtra(formModel.extra as Record<string, unknown>);

      const networkMerged = derivedNetwork
        ? mergeDerivedNetworkFields(
            {
              domain: '',
              ipv4: formModel.ipv4.trim(),
              ipv6: formModel.ipv6.trim(),
              port: formModel.port,
              protocol: '',
              url: '',
            },
            derivedNetwork,
            true,
          )
        : null;

      const payload = {
        name: formModel.name.trim(),
        type: formModel.assetFamily,
        asset_family: formModel.assetFamily,
        organize_id: formModel.organizeId,
        data_number: formModel.dataNumber.trim() || undefined,
        address,
        domain: networkMerged?.domain || undefined,
        ipv4: networkMerged?.ipv4 || undefined,
        ipv6: networkMerged?.ipv6 || undefined,
        url: networkMerged?.url || undefined,
        protocol: networkMerged?.protocol || undefined,
        port: networkMerged?.port ?? formModel.port ?? undefined,
        is_online: formModel.isOnline,
        is_key: formModel.isKey,
        security_protection_level: formModel.securityProtectionLevel || undefined,
        filing_cert_number: formModel.filingCertNumber.trim() || undefined,
        icp_filing_number: formModel.icpFilingNumber.trim() || undefined,
        public_security_filing: formModel.publicSecurityFiling.trim() || undefined,
        data_source: formModel.dataSource,
        operation_org_id: formModel.operationOrgId || undefined,
        extra: Object.keys(extraPayload).length > 0 ? extraPayload : undefined,
        remark: formModel.remark.trim() || undefined,
      };
      if (editingId.value) {
        await updateAsset(editingId.value, payload);
        await saveAssetDynamicForm(editingId.value, formModel.assetFamily);
        message.success('资产已更新');
      } else {
        const created = await createAsset(payload);
        const body = ((created as any)?.data ?? created) as any;
        const assetId = body?.id ?? body?.data?.id;
        if (assetId) await saveAssetDynamicForm(assetId, formModel.assetFamily);
        message.success('资产已创建');
      }
      showEditModal.value = false;
      await Promise.all([reload(), loadOrgTree(), loadRegionScope()]);
    } finally {
      saving.value = false;
    }
  }

  async function handleDelete(id: string) {
    await deleteAsset(id);
    message.success('资产已删除');
    await reload();
  }

  function resolveScanTemplate(rowsToScan: Asset[]) {
    return resolveScanTemplateForAssets(rowsToScan, templates.value);
  }

  function openScanModal(targetRows: Asset[]) {
    if (targetRows.length === 0) return message.warning('请先选择需要扫描的资产');
    resetScanForm();
    scanAssets.value = [...targetRows];
    scanForm.templateId = resolveScanTemplate(targetRows);
    scanForm.name = buildScanTaskName(targetRows);
    scanForm.executorNodeIds = [...EMPTY_SCAN_FORM().executorNodeIds];
    void scanExecutor.loadExecutorNodeOptions();
    showScanModal.value = true;
  }

  function openScanModalByRow(row: Asset) {
    openScanModal([row]);
  }

  function openBatchScanModal() {
    openScanModal(selectedAssets.value);
  }

  function updateScanTemplate(id: string) {
    scanForm.templateId = id;
    const template = templates.value.find((item) => item.id === id);
    if (template) {
      scanForm.name = `${template.name} - ${new Date().toLocaleDateString('zh-CN')}`;
    }
  }

  function setModuleConfigs(configs: Record<string, Record<string, any>>) {
    moduleConfigs.value = configs;
  }

  async function submitScanTask() {
    if (!scanForm.templateId) return message.warning('请选择扫描模板');
    const targets = scanAssets.value.map((item) => assetTarget(item)).filter(Boolean);
    if (targets.length === 0) return message.warning('所选资产缺少可扫描的地址');

    creatingScanTask.value = true;
    try {
      const parameters: Record<string, any> = {
        ...buildScanAssetParameters(scanAssets.value),
      };
      if (Object.keys(moduleConfigs.value).length > 0) parameters.module_configs = moduleConfigs.value;
      if (scanForm.verificationLevel !== 'both') parameters.verification_level = scanForm.verificationLevel;
      if (scanForm.enginePreset) parameters.engine_preset = scanForm.enginePreset;
      appendExecutorNodeParams(parameters, scanForm.executorNodeIds);
      await createTask({
        name: scanForm.name || buildScanTaskName(scanAssets.value),
        targets,
        template_id: scanForm.templateId,
        priority: scanForm.priority,
        executor_node_ids: scanForm.executorNodeIds,
        asset_ids: scanAssets.value.map((item) => item.id),
        parameters,
      });
      message.success('扫描任务已创建');
      showScanModal.value = false;
    } finally {
      creatingScanTask.value = false;
    }
  }

  function openVerifyModal() {
    if (selectedAssets.value.length === 0) {
      return message.warning('请先选择需要下发核验的资产');
    }
    resetVerifyForm();
    showVerifyModal.value = true;
  }

  async function submitVerifyTask() {
    if (!verifyForm.targetOrganizeId) return message.warning('请选择目标单位');

    submittingVerify.value = true;
    try {
      await createVerifyTasks({
        asset_ids: selectedAssets.value.map((item) => item.id),
        source_type: verifyForm.sourceType,
        target_organize_id: verifyForm.targetOrganizeId,
        remark: verifyForm.remark.trim() || undefined,
      });
      message.success('核验任务已创建');
      showVerifyModal.value = false;
      checkedRowKeys.value = [];
    } finally {
      submittingVerify.value = false;
    }
  }

  function openQuickOrganize() {
    resetQuickOrganizeForm();
    showQuickOrganizeModal.value = true;
  }

  async function submitQuickOrganize() {
    if (!quickOrganizeForm.name.trim()) {
      message.warning('请输入单位名称');
      return;
    }
    const usccErr = validateUSCC(quickOrganizeForm.unifiedSocialCreditCode);
    if (usccErr) return message.warning(usccErr);
    quickOrganizeLoading.value = true;
    try {
      const created = await createOrganize({
        name: quickOrganizeForm.name.trim(),
        parent_id: quickOrganizeForm.parentId || undefined,
        unified_social_credit_code: quickOrganizeForm.unifiedSocialCreditCode.trim() || undefined,
      });
      const body = ((created as any)?.data ?? created) as { id?: string };
      const orgId = body?.id;
      if (!orgId) {
        message.error('创建成功但未返回单位 ID');
        return;
      }
      await loadOrgTree();
      formModel.organizeId = orgId;
      await applyOrganizeToUnitExtra(orgId);
      message.success('单位已创建并设为所属单位');
      showQuickOrganizeModal.value = false;
    } catch {
      message.error('新增单位失败');
    } finally {
      quickOrganizeLoading.value = false;
    }
  }

  function openQuickConstruction() {
    resetQuickConstructionForm();
    showQuickConstructionModal.value = true;
  }

  async function submitQuickConstruction() {
    if (!quickConstructionForm.name.trim()) {
      message.warning('请输入单位名称');
      return;
    }
    const phoneErr = validateCNPhone(quickConstructionForm.charge_phone, '联系电话');
    if (phoneErr) return message.warning(phoneErr);

    quickConstructionLoading.value = true;
    try {
      const payload = {
        name: quickConstructionForm.name.trim(),
        location: regionLabelFromCode(quickConstructionForm.location_code) || quickConstructionForm.location,
        address: quickConstructionForm.address.trim(),
        charge_person: quickConstructionForm.charge_person.trim(),
        charge_phone: quickConstructionForm.charge_phone.trim(),
      };
      const created = await createConstruction(payload);
      const item = ((created as any)?.data ?? created) as ConstructionOrg;
      await loadConstructionOptions();

      formModel.operationOrgId = item.id;

      showQuickConstructionModal.value = false;
      message.success('单位已新增并关联到当前资产');
    } finally {
      quickConstructionLoading.value = false;
    }
  }

  const sideActions = useLedgerSideActions({
    buildQueryParams,
    getCheckedRowKeys: () => checkedRowKeys.value,
    getSelectedAssets: () => selectedAssets.value,
    clearSelection: () => {
      checkedRowKeys.value = [];
    },
    reload,
  });

  const batchEdit = useLedgerBatchEdit({
    getCheckedRowKeys: () => checkedRowKeys.value,
    reload,
  });

  function handleBatchAction(key: string) {
    if (key === 'scan') return openBatchScanModal();
    if (key === 'monitor') return void sideActions.sendToMonitor();
    if (key === 'verify') return openVerifyModal();
    if (key === 'edit') return batchEdit.openBatchEditModal();
    if (key === 'delete') return sideActions.confirmBatchDelete();
  }

  function updateImportFile(options: { file: UploadFileInfo }) {
    importFile.value = (options.file.file as File | null) ?? null;
  }

  async function downloadImportTemplateFile() {
    templateDownloading.value = true;
    try {
      const blob = await downloadImportTemplate();
      downloadBlob(blob, 'asset_import_template.xlsx');
    } catch (e: any) {
      message.error(e?.message || '下载模板失败');
    } finally {
      templateDownloading.value = false;
    }
  }

  async function submitImport() {
    if (!importFile.value) return message.warning('请先选择导入文件');
    importLoading.value = true;
    importErrorMessage.value = '';
    importErrorIssues.value = [];
    importErrorCount.value = 0;
    importErrorFailedRows.value = [];
    try {
      await importAssets(importFile.value);
      message.success('导入成功');
      showImportModal.value = false;
      importFile.value = null;
      importErrorMessage.value = '';
      importErrorIssues.value = [];
      importErrorCount.value = 0;
      importErrorFailedRows.value = [];
      pagination.page = 1;
      await Promise.all([reload(), loadOrgTree(), loadRegionScope()]);
      void probeReachabilityAndReload();
    } catch (error) {
      const payload = getImportErrorPayload(error, '导入失败，请检查文件内容后重试');
      importErrorIssues.value = payload.issues;
      importErrorFailedRows.value = payload.failedRows;
      importErrorCount.value = payload.errorCount;
      const tableRows = buildImportErrorTableRows(
        payload.failedRows,
        payload.issues,
      );
      if (tableRows.length > 0) {
        importErrorMessage.value = importErrorSummary(
          payload.errorCount,
          tableRows.length,
        );
      } else {
        importErrorMessage.value = payload.message;
      }
    } finally {
      importLoading.value = false;
    }
  }

  function clearImportError() {
    importErrorMessage.value = '';
    importErrorIssues.value = [];
    importErrorCount.value = 0;
    importErrorFailedRows.value = [];
  }

  function buildProbeParams() {
    const params = buildQueryParams();
    delete (params as { page?: number }).page;
    delete (params as { page_size?: number }).page_size;
    return params;
  }

  async function probeReachabilityAndReload() {
    const assetIds = rows.value
      .filter((row) => row.is_online === true)
      .map((row) => row.id)
      .filter(Boolean);
    await runAssetOnlineSync(buildProbeParams(), assetIds);
    await fetchList();
  }

  async function init() {
    await Promise.all([
      loadOptions(),
      loadOrgTree(),
      loadRegionScope(),
      loadConstructionOptions(),
      loadTemplates(),
      loadEnginePresets(),
    ]);
    resetForm();
    await reload();
    void probeReachabilityAndReload();
  }

  watch(
    () => formModel.assetFamily,
    async (value, oldValue) => {
      if (!showEditModal.value || !value || value === oldValue) return;
      assetDynamicSubmission.value = null;
      assetDynamicFormData.value = {};
      await loadAssetDynamicTemplate(value);
    },
  );

  return {
    loading,
    treeLoading,
    saving,
    importLoading,
    templateDownloading,
    quickConstructionLoading,
    quickOrganizeLoading,
    creatingScanTask,
    submittingVerify,
    sendingToMonitor: sideActions.sendingToMonitor,
    exporting: sideActions.exporting,
    rows,
    checkedRowKeys,
    assetFamilyOptions,
    sourceOptions,
    securityOptions,
    unitTypeOptions,
    industryCategoryOptions,
    constructionOptions,
    orgTreeOptions,
    orgTreeDisplay,
    orgTreeSearchMode,
    searchOrganizes,
    scopeDimension,
    regionTreeOptions,
    industryTreeOptions,
    assetFamilyScopeTreeOptions,
    scopeUsesAssetFamily,
    scopeLabel,
    setScopeDimension,
    resetScopePanel,
    selectedOrgKey,
    selectedRegionKey,
    selectedIndustryKey,
    selectedAssetFamilyKey,
    selectRegion,
    selectIndustry,
    selectAssetFamily,
    scanAssets,
    stats,
    searchForm,
    formModel,
    assetDynamicTemplate,
    assetDynamicSubmission,
    assetDynamicFormData,
    assetDynamicLoading,
    quickConstructionForm,
    quickOrganizeForm,
    scanForm,
    verifyForm,
    batchEditForm: batchEdit.batchEditForm,
    templateOptions,
    enginePresetOptions,
    scanExecutorNodeOptions: scanExecutor.executorNodeOptions,
    scanExecutorNodesLoading: scanExecutor.executorNodesLoading,
    moduleConfigs,
    showEditModal,
    showImportModal,
    importErrorMessage,
    importErrorIssues,
    importErrorCount,
    importErrorFailedRows,
    clearImportError,
    showScanModal,
    showVerifyModal,
    showQuickConstructionModal,
    showQuickOrganizeModal,
    showBatchEditModal: batchEdit.showBatchEditModal,
    showScanAdvanced,
    showScanModuleConfig,
    showAdvancedFilter,
    showMonitorResult: sideActions.showMonitorResult,
    monitorResult: sideActions.monitorResult,
    activeFamily,
    familyTabs: familyFilterOptions,
    isEditing,
    pagination,
    verifySourceOptions: VERIFY_SOURCE_OPTIONS,
    booleanFilterOptions: BOOLEAN_FILTER_OPTIONS,
    batchUpdating: batchEdit.batchUpdating,
    batchEditFieldOptions: batchEdit.batchEditFieldOptions,
    assetFamilyLabel: (value?: string) => optionLabelOf(assetFamilyOptions.value, value),
    sourceLabel: (value?: string) => optionLabelOf(sourceOptions.value, value),
    organizeLabel: (value?: string) => (value ? orgNameMap.value[value] ?? value : '-'),
    assetIdentifier,
    handleSearch,
    handleResetSearch,
    changeFamily,
    reload,
    selectOrg,
    handleCheckedRowKeys,
    openCreateModal,
    openEditModal,
    openBatchScanModal,
    openBatchEditModal: batchEdit.openBatchEditModal,
    openVerifyModal,
    openQuickOrganize,
    openQuickConstruction,
    submitQuickOrganize,
    openScanModalByRow,
    sendToMonitor: sideActions.sendToMonitor,
    updateScanTemplate,
    updateAssetDynamicFormData,
    setModuleConfigs,
    submitForm,
    submitQuickConstruction,
    submitScanTask,
    submitVerifyTask,
    submitBatchEdit: batchEdit.submitBatchEdit,
    handleDelete,
    exportCurrentAssets: sideActions.exportCurrentAssets,
    handleBatchAction,
    handleBatchDelete: sideActions.handleBatchDelete,
    confirmBatchDelete: sideActions.confirmBatchDelete,
    batchDeleting: sideActions.batchDeleting,
    updateImportFile,
    downloadImportTemplateFile,
    submitImport,
    init,
    probeReachabilityAndReload,
  };
}
