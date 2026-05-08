/**
 * 业务枚举集中
 *
 * 所有页面的状态/类型/级别等枚举值映射均集中在这里，
 * 便于统一维护与 i18n。
 *
 * 用法：
 *   import { USER_STATUS } from '#/constants/enums';
 *   import { renderEnum, enumToOptions } from '#/components/table';
 *
 *   renderEnum(row.status, USER_STATUS);
 *   <NSelect :options="enumToOptions(USER_STATUS)" />
 */
import type { EnumMap } from '#/components/table';

// ============== 通用 ==============

/** 启用 / 停用 boolean */
export const ENABLED_MAP: EnumMap = {
  true: { label: '启用', type: 'success' },
  false: { label: '停用', type: 'error' },
  1: { label: '启用', type: 'success' },
  0: { label: '停用', type: 'error' },
};

/** 是 / 否 */
export const YES_NO_MAP: EnumMap = {
  true: { label: '是', type: 'info' },
  false: { label: '否', type: 'default' },
  1: { label: '是', type: 'info' },
  0: { label: '否', type: 'default' },
};

// ============== Identity 模块 ==============

/** 用户 / 组织 / 部门 通用账号状态 */
export const USER_STATUS: EnumMap = {
  normal: { label: '正常', type: 'success' },
  disabled: { label: '停用', type: 'error' },
  locked: { label: '锁定', type: 'warning' },
  pending: { label: '待激活', type: 'info' },
};

export const USER_RELATION_TYPE: EnumMap = {
  organize: { label: '组织', type: 'info' },
  department: { label: '部门', type: 'primary' },
  position: { label: '岗位', type: 'success' },
};

export const MFA_STATE: EnumMap = {
  true: { label: 'MFA 已启用', type: 'info' },
  false: { label: 'MFA 未启用', type: 'default' },
};

// ============== Authorize 模块 ==============

/** 角色数据范围 */
export const DATA_SCOPE_MAP: EnumMap = {
  1: { label: '全部数据', type: 'error' },
  2: { label: '本组织及下属', type: 'warning' },
  3: { label: '本组织', type: 'info' },
  4: { label: '本部门及下属', type: 'primary' },
  5: { label: '本部门', type: 'info' },
  999: { label: '仅本人', type: 'default' },
};

/** 角色可用时间类型 */
export const AVAILABLE_TIME_TYPE: EnumMap = {
  1: { label: '永久', type: 'success' },
  2: { label: '临时', type: 'warning' },
};

/** 菜单类型 */
export const MENU_TYPE_MAP: EnumMap = {
  1: { label: '菜单', type: 'primary' },
  2: { label: 'iframe', type: 'info' },
  3: { label: '额外页面', type: 'warning' },
  4: { label: '按钮', type: 'default' },
};

/** HTTP Method（用于后端 API 列表） */
export const HTTP_METHOD_MAP: EnumMap = {
  GET: { label: 'GET', type: 'success' },
  POST: { label: 'POST', type: 'primary' },
  PUT: { label: 'PUT', type: 'warning' },
  DELETE: { label: 'DELETE', type: 'error' },
  PATCH: { label: 'PATCH', type: 'info' },
  HEAD: { label: 'HEAD', type: 'default' },
  OPTIONS: { label: 'OPTIONS', type: 'default' },
};

// ============== Application 模块 ==============

export const APP_TYPE_MAP: EnumMap = {
  service: { label: '后端服务', type: 'primary' },
  spa: { label: '单页应用', type: 'info' },
  web: { label: '传统 Web', type: 'success' },
};

export const GRANT_TYPE_MAP: EnumMap = {
  authorization_code: { label: '授权码', type: 'primary' },
  password: { label: '密码', type: 'warning' },
  client_credentials: { label: '客户端', type: 'info' },
  refresh_token: { label: '刷新令牌', type: 'success' },
  implicit: { label: '隐式', type: 'default' },
};

// ============== Message 模块 ==============

export const CHANNEL_TYPE_MAP: EnumMap = {
  email: { label: '邮件', type: 'info' },
  sms: { label: '短信', type: 'success' },
  inapp: { label: '站内信', type: 'primary' },
  webhook: { label: 'Webhook', type: 'warning' },
  push: { label: '推送', type: 'info' },
  voice: { label: '语音', type: 'default' },
  wechat: { label: '微信', type: 'success' },
  dingtalk: { label: '钉钉', type: 'primary' },
  feishu: { label: '飞书', type: 'info' },
};

export const CONTENT_TYPE_MAP: EnumMap = {
  text: { label: '纯文本', type: 'default' },
  html: { label: 'HTML', type: 'info' },
  markdown: { label: 'Markdown', type: 'primary' },
  json: { label: 'JSON', type: 'warning' },
};

export const RECIPIENT_TYPE_MAP: EnumMap = {
  user: { label: '用户', type: 'info' },
  organize: { label: '组织', type: 'primary' },
  department: { label: '部门', type: 'success' },
  role: { label: '角色', type: 'warning' },
  all: { label: '全员', type: 'error' },
};

export const RECORD_STATUS_MAP: EnumMap = {
  pending: { label: '排队中', type: 'default' },
  sending: { label: '发送中', type: 'info' },
  success: { label: '成功', type: 'success' },
  failed: { label: '失败', type: 'error' },
  retry: { label: '待重试', type: 'warning' },
  scheduled: { label: '已计划', type: 'info' },
  revoked: { label: '已撤回', type: 'default' },
};

export const ANNOUNCEMENT_STATUS: EnumMap = {
  draft: { label: '草稿', type: 'default' },
  published: { label: '已发布', type: 'success' },
  revoked: { label: '已撤回', type: 'warning' },
  expired: { label: '已过期', type: 'error' },
};

export const PRIORITY_MAP: EnumMap = {
  0: { label: '普通', type: 'default' },
  1: { label: '低', type: 'info' },
  2: { label: '中', type: 'warning' },
  3: { label: '高', type: 'error' },
};

// ============== Platform 模块 ==============

export const DICT_CATEGORY_MAP: EnumMap = {
  system: { label: '系统', type: 'info' },
  business: { label: '业务', type: 'primary' },
  custom: { label: '自定义', type: 'default' },
};

export const PROVIDER_CATEGORY_MAP: EnumMap = {
  storage: { label: '存储', type: 'info' },
  message: { label: '消息', type: 'primary' },
  auth: { label: '认证', type: 'success' },
  captcha: { label: '验证码', type: 'warning' },
  notify: { label: '通知', type: 'default' },
};

export const PROVIDER_TEST_STATUS: EnumMap = {
  success: { label: '正常', type: 'success' },
  failed: { label: '异常', type: 'error' },
  untested: { label: '未测试', type: 'default' },
};

// ============== Storage 模块 ==============

export const STORAGE_PROVIDER_MAP: EnumMap = {
  local: { label: '本地磁盘', type: 'default' },
  oss: { label: '阿里 OSS', type: 'warning' },
  cos: { label: '腾讯 COS', type: 'info' },
  s3: { label: 'AWS S3', type: 'primary' },
  qiniu: { label: '七牛云', type: 'success' },
  obs: { label: '华为 OBS', type: 'error' },
  minio: { label: 'MinIO', type: 'info' },
  upyun: { label: '又拍云', type: 'success' },
};

// ============== Governance 模块 ==============

export const LOG_LEVEL_MAP: EnumMap = {
  debug: { label: 'DEBUG', type: 'default' },
  info: { label: 'INFO', type: 'info' },
  warn: { label: 'WARN', type: 'warning' },
  warning: { label: 'WARNING', type: 'warning' },
  error: { label: 'ERROR', type: 'error' },
  fatal: { label: 'FATAL', type: 'error' },
};

export const RESULT_MAP: EnumMap = {
  success: { label: '成功', type: 'success' },
  failed: { label: '失败', type: 'error' },
  failure: { label: '失败', type: 'error' },
  blocked: { label: '已阻断', type: 'warning' },
  pending: { label: '待处理', type: 'default' },
  partial: { label: '部分成功', type: 'warning' },
};

export const OPERATOR_TYPE_MAP: EnumMap = {
  user: { label: '用户', type: 'info' },
  system: { label: '系统', type: 'primary' },
  api: { label: 'API', type: 'success' },
  job: { label: '定时任务', type: 'warning' },
  external: { label: '外部', type: 'default' },
};

export const RISK_LEVEL_MAP: EnumMap = {
  low: { label: '低风险', type: 'info' },
  medium: { label: '中风险', type: 'warning' },
  high: { label: '高风险', type: 'error' },
  critical: { label: '严重', type: 'error' },
};

export const RISK_CASE_STATE: EnumMap = {
  open: { label: '待处理', type: 'warning' },
  ack: { label: '已确认', type: 'info' },
  investigating: { label: '调查中', type: 'primary' },
  resolved: { label: '已解决', type: 'success' },
  ignored: { label: '已忽略', type: 'default' },
  false_positive: { label: '误报', type: 'default' },
};

export const SYSTEM_LOG_STATUS: EnumMap = {
  success: { label: '成功', type: 'success' },
  failed: { label: '失败', type: 'error' },
  pending: { label: '处理中', type: 'info' },
  skipped: { label: '已跳过', type: 'default' },
};

// ============== Workflow 模块 ==============

/** 流程定义状态 */
export const DEFINITION_STATUS_MAP: EnumMap = {
  draft: { label: '草稿', type: 'default' },
  published: { label: '已发布', type: 'success' },
  deprecated: { label: '已废弃', type: 'warning' },
};

/** 流程实例状态 */
export const INSTANCE_STATUS_MAP: EnumMap = {
  running: { label: '运行中', type: 'primary' },
  completed: { label: '已完成', type: 'success' },
  rejected: { label: '已驳回', type: 'error' },
  cancelled: { label: '已撤回', type: 'warning' },
  suspended: { label: '已挂起', type: 'info' },
  error: { label: '异常', type: 'error' },
};

/** 流程任务状态 */
export const TASK_STATUS_MAP: EnumMap = {
  pending: { label: '待处理', type: 'warning' },
  claimed: { label: '已签收', type: 'info' },
  approved: { label: '已通过', type: 'success' },
  rejected: { label: '已驳回', type: 'error' },
  transferred: { label: '已转办', type: 'default' },
  cancelled: { label: '已取消', type: 'default' },
};

/** 流程任务类型 */
export const TASK_TYPE_MAP: EnumMap = {
  approval: { label: '审批', type: 'primary' },
  fill: { label: '填写', type: 'info' },
  cc: { label: '抄送', type: 'default' },
};

/** 节点类型 */
export const NODE_TYPE_MAP: EnumMap = {
  start_event: { label: '开始', type: 'info' },
  end_event: { label: '结束', type: 'default' },
  approval: { label: '审批', type: 'primary' },
  cc: { label: '抄送', type: 'info' },
  notify: { label: '通知', type: 'info' },
  exclusive_gateway: { label: '排他网关', type: 'warning' },
  parallel_gateway: { label: '并行网关', type: 'success' },
  inclusive_gateway: { label: '包容网关', type: 'info' },
  sub_process: { label: '子流程', type: 'primary' },
  service_task: { label: '服务任务', type: 'warning' },
  timer_event: { label: '定时器', type: 'info' },
  fill_task: { label: '填写', type: 'info' },
  script_task: { label: '脚本', type: 'warning' },
  webhook_task: { label: 'Webhook', type: 'success' },
};

/** 节点执行状态 */
export const NODE_EXEC_STATUS_MAP: EnumMap = {
  pending: { label: '等待中', type: 'default' },
  running: { label: '执行中', type: 'primary' },
  completed: { label: '已完成', type: 'success' },
  skipped: { label: '已跳过', type: 'info' },
  error: { label: '错误', type: 'error' },
};

/** 流转历史操作类型 */
export const HISTORY_ACTION_MAP: EnumMap = {
  start: { label: '发起', type: 'info' },
  approve: { label: '通过', type: 'success' },
  reject: { label: '驳回', type: 'error' },
  transfer: { label: '转办', type: 'warning' },
  rollback: { label: '回退', type: 'warning' },
  cancel: { label: '撤回', type: 'default' },
  cc: { label: '抄送', type: 'info' },
  auto_complete: { label: '自动完成', type: 'success' },
  timeout: { label: '超时', type: 'error' },
};

// ============== 待办事项 ==============

/** 待办状态 */
export const TODO_STATUS_MAP: EnumMap = {
  pending: { label: '待处理', type: 'warning' },
  in_progress: { label: '进行中', type: 'info' },
  completed: { label: '已完成', type: 'success' },
  cancelled: { label: '已取消', type: 'default' },
  expired: { label: '已过期', type: 'error' },
};

/** 待办类型 */
export const TODO_TYPE_MAP: EnumMap = {
  approval: { label: '审批', type: 'primary' },
  task: { label: '任务', type: 'info' },
  reminder: { label: '提醒', type: 'warning' },
  custom: { label: '自定义', type: 'default' },
};

/** 待办来源 */
export const TODO_SOURCE_MAP: EnumMap = {
  system: { label: '系统', type: 'info' },
  manual: { label: '手动', type: 'default' },
  workflow: { label: '工作流', type: 'primary' },
};

/** 待办优先级 */
export const TODO_PRIORITY_MAP: EnumMap = {
  1: { label: '紧急', type: 'error' },
  2: { label: '高', type: 'warning' },
  3: { label: '中', type: 'info' },
  4: { label: '低', type: 'default' },
};

// ============== Auth 模块（OAuth2 / TOTP / WebAuthn / Federation） ==============

export const TOTP_DEVICE_STATUS: EnumMap = {
  active: { label: '活动', type: 'success' },
  disabled: { label: '已禁用', type: 'error' },
};

export const FED_PROVIDER_TYPE: EnumMap = {
  oauth2: { label: 'OAuth2', type: 'primary' },
  oidc: { label: 'OIDC', type: 'info' },
  saml: { label: 'SAML', type: 'warning' },
  ldap: { label: 'LDAP', type: 'success' },
  cas: { label: 'CAS', type: 'default' },
};
