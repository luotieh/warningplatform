# 旧输入到新标准的迁移与供应缺口

本表是字段映射和实施约束，不是完成声明。所有82条需求当前标记not_migrated_to_new_standard。

| 当前来源/结构 | 新字段落点 | 迁移时必须补齐或核验 |
|---|---|---|
| Request.Hits、快照命中raw | alert_matches、sources、artifacts | 原命中主键/字段路径/来源快照版本；不能直接生成contacts |
| PhaseOneMaterials.Contacts及跨快照时间观测 | contacts、coverage | 独立连接/事务身份、单位一致性、去重键、每份来源版本/水位、窗口分母 |
| Scope及原通信资产字段 | scopes、ioc_bindings | 真实asset_id/device_id与端点关系；不能把旧泛化NodeID直接当设备身份 |
| 现有DNS输入 | dns_transactions、relations | 原始问题、事务身份、重传键、真实响应配对、答案到连接关联、PSL版本 |
| 现有HTTP输入/协议记录 | http_transactions、artifacts | 完整请求边界与正文、真实事务身份、响应绑定、重定向来源；未知HTTP材料保留覆盖诊断 |
| 现有Network输入 | connections、sessions、contacts | 连接成功/失败依据、会话边界、实测上下行字节及来源；不能从告警数量估算 |
| 现有TLS输入 | tls_handshakes、tls_references | 握手与连接绑定、证书材料、信任库版本、SNI和指纹来源 |
| store/history.go与report_history.go历史供应 | history_events、coverage、snapshots、ioc_bindings | 同资产设备IOC精确查询、历史记录真实字段绑定、窗口完整性和partial诊断 |
| 现有群组输入 | group_memberships | 真实成员身份、NAT/代理去重、成员通信引用、授权角色来源 |
| 业务配置/授权信息 | authorizations、business_schedules | 生效窗口、业务时区、授权端点/目标/任务类别，未供应不能推断已授权 |
| 现有统计基线 | baselines | 人群/总体、样本量、训练窗口、指标单位、维度键和版本；不是任意单值map |
| 品牌/服务/ASN/证书/词法/域名配置 | 各reference族 | 配置版本、适用期和来源，不存在的参照保持unavailable |
| 规则来源和情报记录 | rule_origins、intel_origins | 原始独立来源及命中/IOC引用；上游信任、审核和有效期不在本模块重审 |
| 现有semantic materials、decode结果 | semantic_materials、artifacts、decode_chains | 同命题来源对象、字段/字节区间、事务方向、每步解码输入输出及版本；禁止截断文本充当完整原文 |
| S07当前缺少的分类材料 | content_classifications | 新增确定性分类或既有DLP/人工标注供应器，含版本、请求体绑定及字节片段；不能用语义模型自证前置条件 |
| S08当前缺少的分块/流量/join | transfer_chunks、transfer_links | 新增可核验应用传输ID/分块序号、独立事务、字节量、关联依据；同IP或相邻时间不足以建立join |
| 历史阶段/活动/协同确认 | stage_campaign_proofs | 有权来源与关联记录、成员和参数单位，不允许LLM填写确证 |
| F/S执行结果与hard_type_scores | 运行时执行上下文和输出合同 | 不进入L2输入；保留F→S依赖、后置类型评分顺序和同源去重 |

新标准尚未接入，现有运行容器继续属于旧实现。接入验收必须分别证明格式转换、字段来源真实、覆盖充分和算法执行正确，不能把Schema验证通过当作这四项同时完成。
