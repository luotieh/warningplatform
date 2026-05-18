<script lang="ts" setup>
import { computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';

import ModuleConfigPanel from '#/views/scan/components/module-config-panel.vue';
import LedgerBatchEditModal from './components/ledger-batch-edit-modal.vue';
import LedgerBatchToolbar from './components/ledger-batch-toolbar.vue';
import LedgerEditModal from './components/ledger-edit-modal.vue';
import LedgerExpiryAlerts from './components/ledger-expiry-alerts.vue';
import LedgerFilterCard from './components/ledger-filter-card.vue';
import LedgerImportModal from './components/ledger-import-modal.vue';
import LedgerMonitorResultModal from './components/ledger-monitor-result-modal.vue';
import LedgerOrgTree from './components/ledger-org-tree.vue';
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
  rows,
  checkedRowKeys,
  assetFamilyOptions,
  sourceOptions,
  securityOptions,
  unitTypeOptions,
  industryCategoryOptions,
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
  quickOrganizeForm,
  scanForm,
  verifyForm,
  batchEditForm,
  templateOptions,
  enginePresetOptions,
  moduleConfigs,
  showEditModal,
  showImportModal,
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

onMounted(async () => {
  await init();
});
</script>

<template>
  <div class="ledger-page">
    <aside class="ledger-page__aside">
      <LedgerOrgTree
        :data="orgTreeOptions"
        :loading="treeLoading"
        :selected-key="selectedOrgKey"
        @reset="selectOrg(null)"
        @update:selected-key="selectOrg"
      />
    </aside>

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
        :selected-org-name="selectedOrgName"
        :show-advanced="showAdvancedFilter"
        @family-change="changeFamily"
        @search="handleSearch"
        @reset="handleResetSearch"
        @toggle="showAdvancedFilter = !showAdvancedFilter"
      />

      <LedgerBatchToolbar
        v-if="checkedRowKeys.length > 0"
        :selected-count="checkedRowKeys.length"
        @edit="openBatchEditModal"
        @monitor="sendToMonitor"
        @scan="openBatchScanModal"
        @verify="openVerifyModal"
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
          @import="showImportModal = true"
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
      @close="showImportModal = false"
      @submit="submitImport"
      @download-template="downloadImportTemplateFile"
      @change="updateImportFile"
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
      :selected-count="checkedRowKeys.length"
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
      :selected-count="checkedRowKeys.length"
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
  gap: 16px;
  grid-template-columns: 260px minmax(0, 1fr);
  min-height: calc(100vh - 120px);
  padding: 16px;
}

.ledger-page__aside {
  min-width: 0;
}

.ledger-page__main {
  display: flex;
  flex-direction: column;
  gap: 16px;
  min-height: 0;
  min-width: 0;
}

/** 主列在栅格内可收缩，避免内部表格按「最小内容宽度」把布局撑破 */
.ledger-page__table-shell {
  min-width: 0;
}

:deep(.ledger-cell--muted) {
  color: var(--n-text-color-3);
}

@media (max-width: 1100px) {
  .ledger-page {
    grid-template-columns: 1fr;
  }
}
</style>
