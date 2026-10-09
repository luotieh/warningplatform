# 历史阶段与协同参数的关联契约

自`evidence-algorithms-0.3`起，F_HIST_STAGE_PROGRESSION和F_HIST_COORD_PARAM_MATCH使用下述更严格的绑定条件。实现位于`history_binding.go`；history_rules.go在完成历史覆盖、时间与来源校验后直接分派，避免把不相关历史事件当作支持引用。

输入由可信快照适配器构建，不由LLM补齐。来源证明使用Provenance，Verified、Complete、Version、SourceIDs均须有效。历史仍限定在[LookbackStart, AsOf)，AsOf不得晚于当前最早命中，当前事件ID、重复事件和未来数据均拒绝。

## 当前阶段必须参加递进

必需字段：CurrentStage、CurrentStageSource、CurrentStageProvenance。CurrentStage只接受scan、exploit、c2、exfil（忽略大小写及外围空格）；scan/exploit归为第1层，c2为第2层，exfil为第3层。CurrentStageSource只接受hard_facts、human、host_evidence、authoritative_external。LLM报告中的event_type或主导类型不能直接抄填为已核验当前阶段。

关联历史必须满足同AssetID，且：

- 未提供当前CampaignID时，使用同一实际IOC关联；不能用同资产或同家族标签替代IOC。历史带有战役ID时，须提供其核验证明；同IOC的历史若具有相互冲突的核验战役归属，则返回unresolved_binding。
- 提供当前CampaignID时，当前及每条候选历史都须有完整CampaignProvenance，并且CampaignID相同。不同战役即使共用IOC也不拼接；核验的同战役允许基础设施轮换。
- 若提供当前Endpoint，其值须与当前Input.Scope.EndpointID一致。当前阶段及关联历史必须来自同一固定快照的可信适配输入。

只有已独立定谳为malicious的历史能提供攻击阶段；审核误报不提供阶段。相关历史未审核或缺少合法阶段时返回missing。其他资产、明确不同IOC或不同战役的历史跳过。

历史按时间排序，当前阶段作为最后一个阶段参与判断。成立须同时满足：至少1条关联恶意历史、历史阶段不回退、当前阶段严格高于最近关联历史阶段。相同时间出现不同层级的历史属于顺序歧义，返回unresolved_binding。

| 历史 → 当前 | 结果 |
| --- | --- |
| 同IOC的scan → 当前c2 | observed |
| 同IOC的scan → c2 → 当前exfil | observed |
| 历史scan → c2，当前仍为c2 | not_observed |
| 历史c2 → scan，当前exfil | not_observed |
| 同资产、不同IOC且无核验战役关系 | not_observed |
| 当前阶段仅来自LLM，或关联证明不足 | missing |

结果记录current_stage_level、latest_historical_stage_level、adjudicated_stages及当前阶段标签，保留当前阶段/战役与历史战役的来源版本、依赖及支持记录。该事实只说明受约束的阶段时序推进，不证明因果攻击链、利用成功或泄露成功。

## 协同参数先绑定，再比较

当前参数仍须CurrentParametersVerified=true、非空且数值有限；parameter_relative_tolerance仍需显式配置。新增必要条件：

1. 提供真实IOC或Endpoint，至少一项；Family等粗标签不能替代实际基础设施。
2. 当前CampaignID及CampaignProvenance有效，历史CampaignID和完整核验证明也有效，并且战役ID相同。
3. 每一个提供的当前基础设施字段均须与历史匹配：提供IOC和Endpoint时，两者都要相同。不能用相同IOC掩盖明确的端点冲突，也不能用相同端点掩盖IOC冲突。历史缺少必需身份字段属于绑定未知，不当作阴性。
4. 资产模式：历史AssetID与当前资产相同，历史不能携带群体参数范围。群体模式：GroupID一致，当前及历史GroupMembershipVerified均为true；双方完整成员集合至少3人且完全相同，成员不能缺失、重复或包含空白ID。当前资产必须属于当前群体；历史若声明单资产，也须属于历史群体。成员顺序不影响匹配，但增加、减少或替换成员都不能按同一群体比较。

GroupMembershipVerified表示已核验**完整成员集合**，不能用采样到的几名成员冒充完整集合。它和CampaignProvenance须由可信适配器根据实际成员记录/独立归属记录生成，禁止用LLM的“同战役”判断反向设置核验标记。

全部绑定成立后，才逐个当前参数比较`abs(current-old)/max(abs(old),1e-9) <= tolerance`。对应历史参数缺少、非有限或未定谳时返回missing；绑定明确不匹配、参数差异超过容限或完整历史中无匹配项时返回not_observed。

结果记录matching_adjudicated_parameters、bound_historical_events、malicious_parameter_matches、false_positive_parameter_matches。审核误报也可能具有相似参数，必须单独记录，不能改写成恶意佐证。观测到参数相似只表示在已核验关联范围内的形态相似，不能据此反推战役归属、感染或攻击成功。

## 兼容性与接入

缺少新增当前阶段或战役证明的旧输入会返回missing；不自动补造字段，不使用旧LLM报告兜底。规则版本升级至0.3，语义规则版本保持0.1。其他57项事实规则及默认只选两项的行为保留。原始证据库/YAML中的旧说明作为兼容草案保存，实际Go计算契约以本文件及运行目录为准。

这次只收紧证据模块的规则和契约。生产历史检索、可信战役/阶段/成员证明构建及报告主流程接入仍需适配。新增回归覆盖误关联、缺项、时序歧义、参数合法性及支持引用隔离，不代表真实告警识别准确率。
