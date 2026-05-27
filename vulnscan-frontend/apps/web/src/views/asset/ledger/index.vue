<script lang="ts" setup>
import { computed, onActivated, onMounted, ref, onUnmounted } from 'vue';
import { useRouter } from 'vue-router';

import ModuleConfigPanel from '#/views/scan/components/module-config-panel.vue';
import LedgerBatchEditModal from './components/ledger-batch-edit-modal.vue';
import LedgerBatchToolbar from './components/ledger-batch-toolbar.vue';
import LedgerEditModal from './components/ledger-edit-modal.vue';
import LedgerExpiryAlerts from './components/ledger-expiry-alerts.vue';
import LedgerFilterCard from './components/ledger-filter-card.vue';
import LedgerImportModal from './components/ledger-import-modal.vue';
import LedgerMonitorResultModal from './components/ledger-monitor-result-modal.vue';
import LedgerScopePanel from './components/ledger-scope-panel.vue';
import LedgerQuickConstructionModal from './components/ledger-quick-construction-modal.vue';
import LedgerQuickOrganizeModal from './components/ledger-quick-organize-modal.vue';
import LedgerScanModal from './components/ledger-scan-modal.vue';
import LedgerStatsGrid from './components/ledger-stats-grid.vue';
import LedgerTableCard from './components/ledger-table-card.vue';
import LedgerVerifyModal from './components/ledger-verify-modal.vue';
import { useLedgerColumns } from './composables/use-ledger-columns';
import { useLedgerPage } from './composables/use-ledger-page';

defineOptions({ name: 'AssetLedgerPage' });

const router = useRouter();
const page = useLedgerPage();
const {
  loading,
  treeLoading,
  saving,
  importLoading,
  templateDownloading,
  creatingScanTask,
  submittingVerify,
  sendingToMonitor,
  exporting,
  batchDeleting,
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
  unitTypeTreeOptions,
  assetFamilyScopeTreeOptions,
  scopeUsesAssetFamily,
  scopeLabel,
  setScopeDimension,
  resetScopePanel,
  selectedOrgKey,
  selectedRegionKey,
  selectedIndustryKey,
  selectedAssetFamilyKey,
  selectedUnitTypeKey,
  selectRegion,
  selectIndustry,
  selectUnitType,
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
  batchEditForm,
  templateOptions,
  enginePresetOptions,
  scanExecutorNodeOptions,
  scanExecutorNodesLoading,
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
  showBatchEditModal,
  showScanAdvanced,
  showScanModuleConfig,
  showAdvancedFilter,
  showMonitorResult,
  monitorResult,
  activeFamily,
  familyTabs,
  isEditing,
  pagination,
  verifySourceOptions,
  booleanFilterOptions,
  quickConstructionLoading,
  quickOrganizeLoading,
  batchUpdating,
  batchEditFieldOptions,
  assetFamilyLabel,
  sourceLabel,
  organizeLabel,
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
  openBatchEditModal,
  openVerifyModal,
  openQuickOrganize,
  openQuickConstruction,
  submitQuickOrganize,
  openScanModalByRow,
  sendToMonitor,
  updateScanTemplate,
  updateAssetDynamicFormData,
  setModuleConfigs,
  submitForm,
  submitQuickConstruction,
  submitScanTask,
  submitVerifyTask,
  submitBatchEdit,
  handleDelete,
  exportCurrentAssets,
  handleBatchAction,
  handleBatchDelete,
  confirmBatchDelete,
  updateImportFile,
  downloadImportTemplateFile,
  submitImport,
  init,
} = page;

const columns = computed(() =>
  useLedgerColumns({
    assetFamilyLabel,
    sourceLabel,
    organizeLabel,
    assetIdentifier,
    onDetail: (row) => router.push(`/asset/detail/${row.id}`),
    onScan: openScanModalByRow,
    onEdit: openEditModal,
    onDelete: handleDelete,
  }),
);

const skipNextActivatedProbe = ref(false);

onMounted(async () => {
  skipNextActivatedProbe.value = true;
  await init();
  skipNextActivatedProbe.value = false;
});

onActivated(async () => {
  if (skipNextActivatedProbe.value) {
    return;
  }
  await Promise.all([page.refreshScopeData(), page.probeReachabilityAndReload()]);
});

const asideWidth = ref(300);
const isResizing = ref(false);

function onResizeStart(e: MouseEvent) {
  e.preventDefault();
  isResizing.value = true;
  const startX = e.clientX;
  const startWidth = asideWidth.value;

  function onMouseMove(ev: MouseEvent) {
    const delta = ev.clientX - startX;
    asideWidth.value = Math.min(Math.max(startWidth + delta, 200), 500);
  }

  function onMouseUp() {
    isResizing.value = false;
    document.removeEventListener('mousemove', onMouseMove);
    document.removeEventListener('mouseup', onMouseUp);
  }

  document.addEventListener('mousemove', onMouseMove);
  document.addEventListener('mouseup', onMouseUp);
}

onUnmounted(() => {
  isResizing.value = false;
});
</script>

<template>
  <div class="ledger-page" :style="{ gridTemplateColumns: `${asideWidth}px auto minmax(0, 1fr)` }">
    <aside class="ledger-page__aside">
      <LedgerScopePanel
        :dimension="scopeDimension"
        :org-tree="orgTreeDisplay"
        :region-tree="regionTreeOptions"
        :industry-tree="industryTreeOptions"
        :unit-type-tree="unitTypeTreeOptions"
        :asset-family-tree="assetFamilyScopeTreeOptions"
        :loading="treeLoading"
        :org-search-mode="orgTreeSearchMode"
        :scope-label="scopeLabel"
        :selected-org-key="selectedOrgKey"
        :selected-region-key="selectedRegionKey"
        :selected-industry-key="selectedIndustryKey"
        :selected-unit-type-key="selectedUnitTypeKey"
        :selected-asset-family-key="selectedAssetFamilyKey"
        @update:dimension="setScopeDimension"
        @org-search="searchOrganizes"
        @org-reset="selectOrg(null)"
        @reset-all="resetScopePanel"
        @update:selected-org-key="selectOrg"
        @update:selected-region-key="selectRegion"
        @update:selected-industry-key="selectIndustry"
        @update:selected-unit-type-key="selectUnitType"
        @update:selected-asset-family-key="selectAssetFamily"
      />
    </aside>

    <div
      class="ledger-page__divider"
      :class="{ 'ledger-page__divider--active': isResizing }"
      @mousedown="onResizeStart"
    />

    <section class="ledger-page__main">
      <LedgerStatsGrid :stats="stats" />

      <LedgerExpiryAlerts
        :assets="rows"
        @detail="(row) => router.push(`/asset/detail/${row.id}`)"
      />

      <LedgerFilterCard
        :active-family="activeFamily"
        :family-options="familyTabs"
        :security-options="securityOptions"
        :source-options="sourceOptions"
        :yes-no-options="booleanFilterOptions"
        :form="searchForm"
        :scope-label="scopeLabel"
        :hide-family-filter="scopeUsesAssetFamily"
        :show-advanced="showAdvancedFilter"
        @family-change="changeFamily"
        @search="handleSearch"
        @reset="handleResetSearch"
        @toggle="showAdvancedFilter = !showAdvancedFilter"
      />

      <LedgerBatchToolbar
        v-if="(checkedRowKeys?.length ?? 0) > 0"
        :selected-count="checkedRowKeys?.length ?? 0"
        :deleting="batchDeleting"
        @edit="openBatchEditModal"
        @monitor="sendToMonitor"
        @scan="openBatchScanModal"
        @verify="openVerifyModal"
        @delete="handleBatchDelete"
      />

      <div class="ledger-page__table-shell">
        <LedgerTableCard
          :columns="columns"
          :data="rows"
          :loading="loading || exporting || sendingToMonitor"
          :pagination="pagination"
          :checked-row-keys="checkedRowKeys"
          @refresh="reload"
          @create="openCreateModal"
          @import="
            () => {
              clearImportError();
              showImportModal = true;
            }
          "
          @export="exportCurrentAssets"
          @batch-action="handleBatchAction"
          @update:checked-row-keys="handleCheckedRowKeys"
        />
      </div>
    </section>

    <LedgerEditModal
      :show="showEditModal"
      :saving="saving"
      :editing="isEditing"
      :form="formModel"
      :dynamic-template="assetDynamicTemplate"
      :dynamic-submission="assetDynamicSubmission"
      :dynamic-form-data="assetDynamicFormData"
      :dynamic-loading="assetDynamicLoading"
      :asset-family-options="assetFamilyOptions"
      :security-options="securityOptions"
      :unit-type-options="unitTypeOptions"
      :industry-category-options="industryCategoryOptions"
      :source-options="sourceOptions"
      :org-tree-options="orgTreeOptions"
      :construction-options="constructionOptions"
      @close="showEditModal = false"
      @quick-organize="openQuickOrganize"
      @quick-construction="openQuickConstruction"
      @submit="submitForm"
      @update:dynamic-form-data="updateAssetDynamicFormData"
      @update:show="(value) => (showEditModal = value)"
    />

    <LedgerImportModal
      :show="showImportModal"
      :loading="importLoading"
      :template-downloading="templateDownloading"
      :error-message="importErrorMessage"
      :error-issues="importErrorIssues"
      :error-count="importErrorCount"
      :error-failed-rows="importErrorFailedRows"
      @close="showImportModal = false"
      @submit="submitImport"
      @download-template="downloadImportTemplateFile"
      @change="
        (payload) => {
          clearImportError();
          updateImportFile(payload);
        }
      "
      @update:show="(value) => (showImportModal = value)"
    />

    <LedgerQuickOrganizeModal
      :show="showQuickOrganizeModal"
      :loading="quickOrganizeLoading"
      :form="quickOrganizeForm"
      :org-tree-options="orgTreeOptions"
      @close="showQuickOrganizeModal = false"
      @submit="submitQuickOrganize"
      @update:show="(value) => (showQuickOrganizeModal = value)"
    />

    <LedgerQuickConstructionModal
      :show="showQuickConstructionModal"
      :loading="quickConstructionLoading"
      :form="quickConstructionForm"
      @close="showQuickConstructionModal = false"
      @submit="submitQuickConstruction"
      @update:show="(value) => (showQuickConstructionModal = value)"
    />

    <LedgerBatchEditModal
      :show="showBatchEditModal"
      :loading="batchUpdating"
      :selected-count="checkedRowKeys?.length ?? 0"
      :form="batchEditForm"
      :field-options="batchEditFieldOptions"
      :source-options="sourceOptions"
      :security-options="securityOptions"
      :org-tree-options="orgTreeOptions"
      @close="showBatchEditModal = false"
      @submit="submitBatchEdit"
      @update:show="(value) => (showBatchEditModal = value)"
    />

    <LedgerScanModal
      :show="showScanModal"
      :creating="creatingScanTask"
      :show-advanced="showScanAdvanced"
      :form="scanForm"
      :assets="scanAssets"
      :template-options="templateOptions"
      :engine-preset-options="enginePresetOptions"
      :executor-node-options="scanExecutorNodeOptions"
      :executor-nodes-loading="scanExecutorNodesLoading"
      :module-config-count="Object.keys(moduleConfigs).length"
      @close="showScanModal = false"
      @submit="submitScanTask"
      @advanced="showScanAdvanced = !showScanAdvanced"
      @module-config="showScanModuleConfig = true"
      @update:show="(value) => (showScanModal = value)"
      @update:template="updateScanTemplate"
    />

    <LedgerVerifyModal
      :show="showVerifyModal"
      :loading="submittingVerify"
      :form="verifyForm"
      :source-options="verifySourceOptions"
      :org-tree-options="orgTreeOptions"
      :selected-count="checkedRowKeys?.length ?? 0"
      @close="showVerifyModal = false"
      @submit="submitVerifyTask"
      @update:show="(value) => (showVerifyModal = value)"
    />

    <LedgerMonitorResultModal
      :show="showMonitorResult"
      :result="monitorResult"
      @close="showMonitorResult = false"
      @update:show="(value) => (showMonitorResult = value)"
    />

    <ModuleConfigPanel
      v-model:show="showScanModuleConfig"
      :module-configs="moduleConfigs"
      @save="setModuleConfigs"
    />
  </div>
</template>

<style scoped>
.ledger-page {
  display: grid;
  gap: 0;
  grid-template-columns: 300px auto minmax(0, 1fr);
  min-height: calc(100vh - 120px);
  padding: 16px;
  column-gap: 0;
}

.ledger-page__aside {
  min-width: 0;
  padding-right: 0;
}

.ledger-page__divider {
  width: 8px;
  cursor: col-resize;
  position: relative;
  flex-shrink: 0;
  user-select: none;
  z-index: 1;
}

.ledger-page__divider::after {
  content: '';
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 2px;
  height: 32px;
  border-radius: 1px;
  background: var(--n-border-color, #e0e0e6);
  transition: background 0.2s, height 0.2s;
}

.ledger-page__divider:hover::after,
.ledger-page__divider--active::after {
  background: var(--n-primary-color, #2080f0);
  height: 48px;
}

.ledger-page__main {
  display: flex;
  flex-direction: column;
  gap: 16px;
  min-height: 0;
  min-width: 0;
  padding-left: 8px;
}

.ledger-page__table-shell {
  min-width: 0;
}

:deep(.ledger-cell--muted) {
  color: var(--n-text-color-3);
}

:deep(.ledger-row-actions .ledger-row-action) {
  padding: 0 6px;
}

:deep(.ledger-row-actions .ledger-row-action--emphasize) {
  font-weight: 500;
}

@media (max-width: 1100px) {
  .ledger-page {
    grid-template-columns: 1fr !important;
  }

  .ledger-page__divider {
    display: none;
  }

  .ledger-page__main {
    padding-left: 0;
  }
}
</style>
