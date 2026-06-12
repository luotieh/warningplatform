<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import {
  NDrawer, NDrawerContent, NForm, NFormItem, NInput, NSelect,
  NDatePicker, NButton, NSpace, NDescriptions, NDescriptionsItem,
  NTag, NDivider,
  useMessage,
} from 'naive-ui';
import type { SelectOption } from 'naive-ui';
import {
  createOrder,
  DispatchTypeLabels, type DispatchType, type DispatchSourceType,
  SourceTypeLabels,
  getContactList, type DispatchContact,
  getIAMUserList, type IAMUser,
} from '#/api/dispatch';

const props = defineProps<{
  show: boolean;
  sourceType?: DispatchSourceType;
  sourceId?: string;
  sourceTitle?: string;
  defaultType?: DispatchType;
  sourceDetail?: Record<string, any>;
}>();

const emit = defineEmits<{
  (e: 'update:show', val: boolean): void;
  (e: 'created', order: any): void;
}>();

const message = useMessage();
const submitting = ref(false);

const form = ref({
  title: '',
  description: '',
  type: 'vuln_retest' as DispatchType,
  priority: 3,
  assignee_type: 'internal',
  assignee_name: '',
  assignee_contact: '',
  assignee_id: '',
  deadline: null as number | null,
});

watch(() => props.show, (val) => {
  if (val) {
    form.value = {
      title: props.sourceTitle ? `[${props.sourceTitle}] 任务派发` : '',
      description: '',
      type: props.defaultType || 'vuln_retest',
      priority: 3,
      assignee_type: 'internal',
      assignee_name: '',
      assignee_contact: '',
      assignee_id: '',
      deadline: null,
    };
    loadUsers();
    loadContacts();
  }
});

const typeOptions: SelectOption[] = Object.entries(DispatchTypeLabels).map(([v, l]) => ({ value: v, label: l }));

// ─── IAM 用户选择 ───

const users = ref<IAMUser[]>([]);
const usersLoading = ref(false);

async function loadUsers() {
  usersLoading.value = true;
  try {
    const res = await getIAMUserList({ page: 1, page_size: 200 });
    users.value = res.items;
  } catch {
  } finally {
    usersLoading.value = false;
  }
}

const userOptions = computed<SelectOption[]>(() =>
  users.value.map((u) => ({
    value: u.user_id,
    label: `${u.name || u.account} (${u.account})`,
    user: u,
  })),
);

function onUserSelect(userId: string) {
  const u = users.value.find((x) => x.user_id === userId);
  if (u) {
    form.value.assignee_id = u.user_id;
    form.value.assignee_name = u.name || u.account;
    form.value.assignee_contact = u.email || u.phone || '';
  }
}

// ─── 联系人选择 ───

const contacts = ref<DispatchContact[]>([]);

async function loadContacts() {
  try {
    const res = await getContactList({ page: 1, page_size: 100 });
    contacts.value = res.items;
  } catch {}
}

const contactOptions = computed<SelectOption[]>(() =>
  contacts.value.map((c) => ({
    value: c.id,
    label: `${c.name} - ${c.company || ''} (${c.email || c.phone || ''})`,
  })),
);

function onContactSelect(id: string) {
  const c = contacts.value.find((x) => x.id === id);
  if (c) {
    form.value.assignee_name = c.name;
    form.value.assignee_contact = c.email || c.phone;
    form.value.assignee_id = c.id;
  }
}

// ─── 提交 ───

async function handleSubmit() {
  if (!form.value.title) {
    message.warning('请填写标题');
    return;
  }
  submitting.value = true;
  try {
    const payload: Record<string, any> = {
      ...form.value,
      source_type: props.sourceType || 'manual',
      source_id: props.sourceId || '',
      source_title: props.sourceTitle || '',
    };
    if (form.value.deadline) {
      payload.deadline = new Date(form.value.deadline).toISOString().slice(0, 19).replace('T', ' ');
    } else {
      delete payload.deadline;
    }
    const res = await createOrder(payload);
    message.success('派发单创建成功');
    emit('update:show', false);
    emit('created', res);
  } catch (e: any) {
    message.error(e?.message || '创建失败');
  } finally {
    submitting.value = false;
  }
}
</script>

<template>
  <NDrawer :show="show" :width="560" placement="right" @update:show="emit('update:show', $event)">
    <NDrawerContent title="创建派发单" :native-scrollbar="false">
      <!-- 关联来源信息 -->
      <div v-if="sourceType && sourceType !== 'manual'" style="margin-bottom: 16px">
        <NDescriptions :column="1" label-placement="left" bordered size="small">
          <NDescriptionsItem label="来源类型">
            <NTag size="small" :bordered="false">{{ SourceTypeLabels[sourceType] || sourceType }}</NTag>
          </NDescriptionsItem>
          <NDescriptionsItem v-if="sourceTitle" label="来源">
            {{ sourceTitle }}
          </NDescriptionsItem>
          <template v-if="sourceDetail">
            <NDescriptionsItem v-if="sourceDetail.severity" label="严重程度">
              {{ sourceDetail.severity }}
            </NDescriptionsItem>
            <NDescriptionsItem v-if="sourceDetail.address || sourceDetail.target" label="资产/目标">
              {{ sourceDetail.address || sourceDetail.target }}
            </NDescriptionsItem>
            <NDescriptionsItem v-if="sourceDetail.status" label="状态">
              {{ sourceDetail.status }}
            </NDescriptionsItem>
          </template>
        </NDescriptions>
        <NDivider style="margin: 12px 0" />
      </div>

      <NForm :model="form" label-placement="left" label-width="auto">
        <NFormItem label="标题" required>
          <NInput v-model:value="form.title" placeholder="请输入派发单标题" />
        </NFormItem>
        <NFormItem label="类型">
          <NSelect v-model:value="form.type" :options="typeOptions" />
        </NFormItem>
        <NFormItem label="优先级">
          <NSelect v-model:value="form.priority"
            :options="[{value:1,label:'最低'},{value:2,label:'低'},{value:3,label:'中'},{value:4,label:'高'},{value:5,label:'紧急'}]" />
        </NFormItem>
        <NFormItem label="描述">
          <NInput v-model:value="form.description" type="textarea" :rows="3" placeholder="详细描述" />
        </NFormItem>

        <NDivider style="margin: 8px 0 16px">指派处理人</NDivider>

        <NFormItem label="选择用户" required>
          <NSelect v-model:value="form.assignee_id" :options="userOptions" :loading="usersLoading"
            filterable clearable placeholder="从系统用户中选择处理人"
            @update:value="onUserSelect" />
        </NFormItem>
        <NFormItem label="辅助：联系人库">
          <NSelect :options="contactOptions" filterable clearable
            placeholder="或从联系人库选择（可选）"
            @update:value="onContactSelect" />
        </NFormItem>
        <NFormItem label="处理人姓名">
          <NInput v-model:value="form.assignee_name" placeholder="自动填充，可手动修改" />
        </NFormItem>
        <NFormItem label="联系方式">
          <NInput v-model:value="form.assignee_contact" placeholder="邮箱或手机" />
        </NFormItem>
        <NFormItem label="截止时间">
          <NDatePicker v-model:value="form.deadline" type="datetime" clearable style="width: 100%" />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="emit('update:show', false)">取消</NButton>
          <NButton type="primary" :loading="submitting" @click="handleSubmit">创建</NButton>
        </NSpace>
      </template>
    </NDrawerContent>
  </NDrawer>
</template>
