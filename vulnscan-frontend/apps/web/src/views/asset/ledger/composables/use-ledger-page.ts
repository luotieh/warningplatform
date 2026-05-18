import type { PaginationProps, TreeOption, UploadFileInfo } from 'naive-ui';

import { computed, reactive, ref, watch } from 'vue';
import { useMessage } from 'naive-ui';

import {
  createAsset,
  deleteAsset,
  getAssetList,
  getAssetStats,
  downloadImportTemplate,
  importAssets,
  updateAsset,
  type Asset,
} from '#/api/asset';
import {
  createConstruction,
  createVerifyTasks,
  getConstructionList,
  getOrganizeTree,
  type ConstructionOrg,
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
import { regionLabelFromCode } from '#/utils/region';

import {
  BOOLEAN_FILTER_OPTIONS,
  DEFAULT_ASSET_FAMILY_OPTIONS,
  DEFAULT_SOURCE_OPTIONS,
  EMPTY_LEDGER_EXTRA,
  EMPTY_LEDGER_FORM,
  EMPTY_LEDGER_STATS,
  EMPTY_QUICK_CONSTRUCTION_FORM,
  EMPTY_SCAN_FORM,
  EMPTY_VERIFY_FORM,
  VERIFY_SOURCE_OPTIONS,
} from '../constants';
import { assetTarget, buildScanTaskName, resolveScanTemplate as resolveScanTemplateForAssets } from '../scan-utils';
import type {
  LedgerConstructionForm,
  LedgerFormModel,
  LedgerOption,
  LedgerScanForm,
  LedgerSearchForm,
  LedgerStats,
  LedgerVerifyForm,
} from '../types';
import { downloadBlob } from '../file-utils';
import { appendFallbackOption, assetIdentifier, flattenOrgTree, normalizeOrgTree, optionLabelOf } from '../utils';
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
  const creatingScanTask = ref(false);
  const submittingVerify = ref(false);
  const rows = ref<Asset[]>([]);
  const checkedRowKeys = ref<string[]>([]);
  const assetFamilyOptions = ref<LedgerOption[]>([...DEFAULT_ASSET_FAMILY_OPTIONS]);
  const sourceOptions = ref<LedgerOption[]>([...DEFAULT_SOURCE_OPTIONS]);
  const securityOptions = ref<LedgerOption[]>([]);
  const constructionOptions = ref<LedgerOption[]>([]);
  const orgTreeOptions = ref<TreeOption[]>([]);
  const orgNameMap = ref<Record<string, string>>({});
  const selectedOrgKey = ref<string | null>(null);
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
    regionCode: null,
    riskScoreMin: null,
    riskScoreMax: null,
    isKey: '',
  });
  const formModel = reactive<LedgerFormModel>(EMPTY_LEDGER_FORM());
  const quickConstructionForm = reactive<LedgerConstructionForm>(EMPTY_QUICK_CONSTRUCTION_FORM());
  const scanForm = reactive<LedgerScanForm>(EMPTY_SCAN_FORM());
  const verifyForm = reactive<LedgerVerifyForm>(EMPTY_VERIFY_FORM());
  const showEditModal = ref(false);
  const showImportModal = ref(false);
  const showScanModal = ref(false);
  const showVerifyModal = ref(false);
  const showQuickConstructionModal = ref(false);
  const showScanAdvanced = ref(false);
  const showScanModuleConfig = ref(false);
  const showAdvancedFilter = ref(false);
  const quickConstructionTarget = ref<'construction' | 'operation'>('construction');
  const linkQuickConstructionToBoth = ref(false);
  const editingId = ref<string | null>(null);
  const importFile = ref<File | null>(null);

  const isEditing = computed(() => !!editingId.value);
  const selectedOrgName = computed(() =>
    selectedOrgKey.value ? orgNameMap.value[selectedOrgKey.value] ?? selectedOrgKey.value : '',
  );
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
    linkQuickConstructionToBoth.value = quickConstructionTarget.value === 'construction';
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
    [assetFamilyOptions.value, sourceOptions.value, securityOptions.value] = await Promise.all([
      loadDictOptions('asset_family', DEFAULT_ASSET_FAMILY_OPTIONS, { label: '其他', value: 'other' }),
      loadDictOptions('asset_data_source', DEFAULT_SOURCE_OPTIONS, { label: '其他', value: 'other' }),
      loadDictOptions('asset_security_level'),
    ]);
  }

  async function loadOrgTree() {
    treeLoading.value = true;
    try {
      const tree = await getOrganizeTree();
      const options = normalizeOrgTree(Array.isArray(tree) ? tree : []);
      orgTreeOptions.value = options;
      orgNameMap.value = flattenOrgTree(options);
    } catch {
      orgTreeOptions.value = [];
      orgNameMap.value = {};
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

  function buildQueryParams() {
    return {
      page: pagination.page,
      page_size: pagination.pageSize,
      keyword: searchForm.keyword || undefined,
      organize_id: selectedOrgKey.value || undefined,
      asset_family: searchForm.assetFamily || undefined,
      security_protection_level: searchForm.securityLevel || undefined,
      data_source: searchForm.dataSource || undefined,
      region_code: searchForm.regionCode || undefined,
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
    searchForm.regionCode = null;
    searchForm.riskScoreMin = null;
    searchForm.riskScoreMax = null;
    searchForm.isKey = '';
    activeFamily.value = 'all';
    selectedOrgKey.value = null;
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

  function handleCheckedRowKeys(keys: string[]) {
    checkedRowKeys.value = keys;
  }

  async function openCreateModal() {
    resetForm();
    resetAssetDynamicForm();
    await loadAssetDynamicTemplate(formModel.assetFamily);
    showEditModal.value = true;
  }

  async function openEditModal(row: Asset) {
    editingId.value = row.id;
    Object.assign(formModel, {
      name: row.name ?? '',
      assetFamily: row.asset_family ?? assetFamilyOptions.value[0]?.value ?? 'ip',
      organizeId: row.organize_id ?? '',
      dataNumber: row.data_number ?? '',
      address: row.address ?? row.domain ?? '',
      ipv4: row.ipv4 ?? '',
      ipv6: row.ipv6 ?? '',
      regionCode: row.region_code ?? (row.extra as Record<string, unknown> | undefined)?.region_code?.toString() ?? null,
      port: row.port ?? null,
      isOnline: row.is_online ?? true,
      isKey: row.is_key ?? false,
      responsibleUserName: row.responsible_user_name ?? '',
      dataSource: row.data_source ?? sourceOptions.value[0]?.value ?? 'manual_import',
      securityProtectionLevel: row.security_protection_level ?? '',
      filingCertNumber: row.filing_cert_number ?? '',
      icpFilingNumber: row.icp_filing_number ?? '',
      publicSecurityFiling: row.public_security_filing ?? '',
      constructionOrgId: row.construction_org_id ?? '',
      operationOrgId: row.operation_org_id ?? '',
      remark: row.remark ?? '',
      extra: { ...EMPTY_LEDGER_EXTRA(), ...(row.extra ?? {}) },
    });
    resetAssetDynamicForm();
    await loadAssetDynamicTemplate(formModel.assetFamily);
    await loadAssetDynamicSubmission(row.id);
    showEditModal.value = true;
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

    const address = resolvedAssetAddress();

    saving.value = true;
    try {
      const extraPayload: Record<string, unknown> = { ...formModel.extra };
      if (formModel.regionCode) {
        extraPayload.region_code = formModel.regionCode;
      } else {
        delete extraPayload.region_code;
      }

      const payload = {
        name: formModel.name.trim(),
        type: formModel.assetFamily,
        asset_family: formModel.assetFamily,
        organize_id: formModel.organizeId,
        data_number: formModel.dataNumber.trim() || undefined,
        address,
        ipv4: formModel.ipv4.trim() || undefined,
        ipv6: formModel.ipv6.trim() || undefined,
        port: formModel.port ?? undefined,
        is_online: formModel.isOnline,
        is_key: formModel.isKey,
        security_protection_level: formModel.securityProtectionLevel || undefined,
        filing_cert_number: formModel.filingCertNumber.trim() || undefined,
        icp_filing_number: formModel.icpFilingNumber.trim() || undefined,
        public_security_filing: formModel.publicSecurityFiling.trim() || undefined,
        responsible_user_name: formModel.responsibleUserName.trim() || undefined,
        data_source: formModel.dataSource,
        construction_org_id: formModel.constructionOrgId || undefined,
        operation_org_id: formModel.operationOrgId || undefined,
        extra: extraPayload,
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
      await reload();
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
      const parameters: Record<string, any> = {};
      if (Object.keys(moduleConfigs.value).length > 0) parameters.module_configs = moduleConfigs.value;
      if (scanForm.verificationLevel !== 'both') parameters.verification_level = scanForm.verificationLevel;
      if (scanForm.enginePreset) parameters.engine_preset = scanForm.enginePreset;
      await createTask({
        name: scanForm.name || buildScanTaskName(scanAssets.value),
        targets,
        template_id: scanForm.templateId,
        priority: scanForm.priority,
        parameters: Object.keys(parameters).length > 0 ? parameters : undefined,
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

  function openQuickConstruction(target: 'construction' | 'operation') {
    quickConstructionTarget.value = target;
    resetQuickConstructionForm();
    showQuickConstructionModal.value = true;
  }

  function useConstructionAsOperation() {
    if (!formModel.constructionOrgId) {
      message.warning('请先选择建设单位');
      return;
    }
    formModel.operationOrgId = formModel.constructionOrgId;
  }

  function useOperationAsConstruction() {
    if (!formModel.operationOrgId) {
      message.warning('请先选择运维单位');
      return;
    }
    formModel.constructionOrgId = formModel.operationOrgId;
  }

  async function submitQuickConstruction() {
    if (!quickConstructionForm.name.trim()) {
      message.warning('请输入单位名称');
      return;
    }

    quickConstructionLoading.value = true;
    try {
      const payload = {
        name: quickConstructionForm.name.trim(),
        location: regionLabelFromCode(quickConstructionForm.location_code) || quickConstructionForm.location,
        address: quickConstructionForm.address.trim(),
        charge_person: quickConstructionForm.charge_person.trim(),
        charge_phone: quickConstructionForm.charge_phone.trim(),
        security_filing: quickConstructionForm.security_filing.trim(),
      };
      const created = await createConstruction(payload);
      const item = ((created as any)?.data ?? created) as ConstructionOrg;
      await loadConstructionOptions();

      if (quickConstructionTarget.value === 'construction') {
        formModel.constructionOrgId = item.id;
        if (linkQuickConstructionToBoth.value) formModel.operationOrgId = item.id;
      } else {
        formModel.operationOrgId = item.id;
        if (linkQuickConstructionToBoth.value) formModel.constructionOrgId = item.id;
      }

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
    if (key === 'delete') return void sideActions.handleBatchDelete();
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
    try {
      await importAssets(importFile.value);
      message.success('导入成功');
      showImportModal.value = false;
      importFile.value = null;
      await reload();
    } finally {
      importLoading.value = false;
    }
  }

  async function init() {
    await Promise.all([
      loadOptions(),
      loadOrgTree(),
      loadConstructionOptions(),
      loadTemplates(),
      loadEnginePresets(),
    ]);
    resetForm();
    await reload();
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
    creatingScanTask,
    submittingVerify,
    sendingToMonitor: sideActions.sendingToMonitor,
    exporting: sideActions.exporting,
    rows,
    checkedRowKeys,
    assetFamilyOptions,
    sourceOptions,
    securityOptions,
    constructionOptions,
    orgTreeOptions,
    selectedOrgKey,
    selectedOrgName,
    scanAssets,
    stats,
    searchForm,
    formModel,
    assetDynamicTemplate,
    assetDynamicSubmission,
    assetDynamicFormData,
    assetDynamicLoading,
    quickConstructionForm,
    scanForm,
    verifyForm,
    batchEditForm: batchEdit.batchEditForm,
    templateOptions,
    enginePresetOptions,
    moduleConfigs,
    showEditModal,
    showImportModal,
    showScanModal,
    showVerifyModal,
    showQuickConstructionModal,
    showBatchEditModal: batchEdit.showBatchEditModal,
    showScanAdvanced,
    showScanModuleConfig,
    showAdvancedFilter,
    showMonitorResult: sideActions.showMonitorResult,
    monitorResult: sideActions.monitorResult,
    quickConstructionTarget,
    linkQuickConstructionToBoth,
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
    openQuickConstruction,
    openScanModalByRow,
    useConstructionAsOperation,
    useOperationAsConstruction,
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
    updateImportFile,
    downloadImportTemplateFile,
    submitImport,
    init,
  };
}
