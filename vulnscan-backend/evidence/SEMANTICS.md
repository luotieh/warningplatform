# 23个语义槽位

后端语义规则版本为`evidence-semantics-0.1`。23个槽位均已实现前提解析、任务构建、模型返回校验及失败降级；其中18个解释具体行为，5个只记录替代解释、阶段缺口或历史参考。槽位使用`(id,target,subtype)`作为唯一键，S12和S13各占两个槽位。

语义不是新的统计算法。59项事实规则的结果保持原样；语义解释使用可追溯的实际片段、字段与背景，不重算事实，不输出评分、概率、类型门槛或自动排除决定。LLM的解释仍需复核，引用合法及强度合规不等于语义判断正确，也不证明攻击成功。

## 文件与调用边界

- `semantic_types.go`：独立输入、任务、模型接口及输出契约。
- `semantic_catalog.go`：23项运行目录；与旧版YAML中的未启用标记分开维护。
- `semantic_prerequisites.go`：按槽位检查字段、事务、解码链、群体、历史和事实前提。
- `semantic_engine.go`：按需选择、上下文预算、单批调用、超时和失败记录。
- `semantic_validation.go`：严格JSON、引用、逐字摘录、强度及同命题去重。
- `traffic/internal/client/evidence_semantic.go`：现有LLM客户端的薄适配器，强制执行本次输出token预算并拒绝被截断的回答。

`SemanticEngine`不持有数据库、HTTP配置或traffic领域对象。适配器从固定快照获取资料，经核验、字段级脱敏后组成`SemanticRequest`。`Plan`只检查及构建任务，不调用模型；`Evaluate`接受注入的`SemanticModel`，最多进行一次批量调用。构造后可复用及并发调用，调用期间不得修改输入；自定义tokenizer也须能安全并发使用。

```go
semanticEngine, err := evidence.NewSemanticEngine(evidence.DefaultSemanticConfig())
if err != nil { return err }

// verifiedSubjects由可信快照适配器构建；不是LLM摘要或外部自报结论。
request := evidence.SemanticRequest{
    EventID: eventID,
    SnapshotVersion: snapshotVersion,
    Subjects: verifiedSubjects,
    Slots: []evidence.SlotKey{
        {ID: "S01", Target: "c2.command_intent"},
        {ID: "S13", Target: "payload.decoded_intent", Subtype: "command"},
    },
}
result, err := semanticEngine.Evaluate(ctx, request,
    client.EvidenceSemanticModel{Client: configuredLLMClient})
```

上例在traffic内部调用位置使用`client`；其他模块可实现同一接口，避免导入traffic的internal包。`Complete(ctx, SemanticCall)`必须执行`MaxOutputTokens`，对输出被截断、传输失败或模型异常返回错误。普通`Chat`接口不能保证这个契约，因此没有直接作为执行接口。

`Slots=nil`自动检查23项的适用性，只送达满足前提且预算允许的任务；显式空slice执行零项；显式列表按请求顺序取得预算。未知键、重复键、仅提供S12而省略目标/子类型均报错。未满足前提记录`skipped`，不触发模型。模型不可用、超时、未返回某任务记录`unavailable`；非法返回记录`rejected`；通过引用与强度检查记录`accepted`。

## 逐项前提

以下kind对应`SemanticMaterial.Kind`，必须具有核验来源、版本、字段路径和脱敏文本。事实前提必须是同scope、窗口、快照的`observed/eligible`Finding，不接受`missing`或`not_observed`充当阳性依据。

| 槽位 | 目标/子类型 | 材料及检查 |
| --- | --- | --- |
| S01 | c2.command_intent | protocol_request＋direction，实际方向及事务；strong须有效双向pair和请求/应答双引文 |
| S02 | c2.command_exchange | protocol_request＋protocol_response＋pair，事务一致、方向相反，真实协议正文 |
| S03 | c2.ua_behavior_conflict | ua＋protocol_request；F_HTTP_ENDPOINT_REPEAT成立；F_HTTP_UA_RARITY已成立时标记不可累加 |
| S04 | c2.dns_encoded_intent | domain＋decode＋decoded_payload；F_DNS_ENCODED_LABEL成立；域名绑定编码输入，程序验证完整解码链 |
| S05 | phishing.deception | page＋host＋brand_authorization；缺少绑定Host/授权背景的brand_relation时最多weak |
| S06 | phishing.credential_action | credential_fields＋protocol_request，字段名/方法/目的绑定同请求；F_CRED_POST_STRUCTURE、F_FORM_CROSSSITE、F_REDIRECT_CHAIN任一成立 |
| S07 | exfil.sensitive_upload | 完整protocol_request＋direction＋volume＋content_classification；同事务、真实外发方向与正体量 |
| S08 | exfil.chunk_sequence | chunk＋volume＋transfer_join；至少两事务可靠join、独立块序号及逐块相同体量；禁止拼接无关命中 |
| S09 | exploit.payload_intent | protocol_request＋parsed_payload＋direction，实际方法、目的和协议，载荷与请求同事务 |
| S10 | protocol.response_meaning | 同事务protocol_request＋protocol_response＋pair；HTTP200本身不能证明执行 |
| S11 | mining.protocol_intent | stratum_request＋stratum_response＋pair；解析真实JSON方法/参数/返回，请求响应id及其类型一致；标记不重复计入协议命题 |
| S12 | c2.domain_lexical / dga_lexical | domain＋lexical_context；仅词形最多weak；与成立的F_DGA_LEXICAL不可累加 |
| S12 | phishing.deception / brand_semantic_impostor | brand＋host＋brand_authorization；关系绑定不足最多weak；与S05及品牌算法同命题去重 |
| S13 | payload.decoded_intent / command | decode＋decoded_payload＋protocol_request＋direction；解码结果绑定实际请求；strong沿用S01双向条件 |
| S13 | payload.decoded_intent / other | decode＋decoded_payload＋operation_context；操作背景绑定解码结果；解码本身不证明恶意 |
| S14 | review.benign_alternative | protocol_request＋asset_role＋task_context及接受的事实；仅记录异议 |
| S15 | review.stage_and_gaps | visibility＋gaps及接受的事实状态；缺项不能改写成阴性或成功 |
| BT-S01 | botnet.coordination | 核验群体2～5个不同资产的角色/行为摘要；F_TIME_COORDINATION、F_COORD_PATTERN_RECURRENCE、F_COORD_FANOUT、F_INFECTION_CHAIN任一成立；不能替代硬门槛 |
| SC01 | c2.role_schedule_conflict | asset_role＋business_schedule＋time_distribution或workhours_active；必须有实际角色字段，夜间运行不自动异常 |
| SC02 | botnet.group_alternative | 核验群体2～5个不同资产的角色/行为摘要；仅供人工替代解释 |
| SC03 | phishing.brand_field_conflict | brand＋credential_fields＋brand_authorization，逐字引用实际品牌及字段；不能替代欺骗/行动门槛 |
| R06 | history.same_campaign | 1～5条独立history＋current_pattern；定谳来源仅human、host_evidence、authoritative_external；引用全部adjudication_id |
| R07 | history.false_positive_match | 同R06，并要求审核的FalsePositive历史；不能自动扣分 |

S14、S15、SC02、R06、R07为解释专用，`strength`强制为`none`，并保留`ExplanationOnly=true`。普通槽位的`none/weak/medium/strong`描述证据解释强度，不转换为分数。`neutral`必须为`none`。被截断或不完整的材料最多支持weak；凭据提交、外传、分块和历史任务的必需材料本身不完整则跳过。预算裁剪后的实际送达文本也会触发weak上限。

## 材料与归属契约

每个`SemanticSubject`代表一个明确命题，具有`ID`、由适配器分配的`PropositionID`、已解析`Scope`和半开窗口。各材料携带相同scope/window/snapshot；三者任一不符即拒绝请求。一个subject中同kind的普通必需材料有多份会作为歧义跳过，应分成不同命题；chunk、volume、group_member和history允许有多份。多个独立操作必须分配不同PropositionID。

材料的`Provenance.Verified/Complete/Version/SourceIDs`必须由可信适配器核验设置，不能从流量正文、客户端参数或LLM返回复制。`Redacted=true`同样是适配器的脱敏契约，不是自动脱敏完成的证明；必须事先移除密码、凭据值、Cookie、Token、敏感上传内容等，只保留字段名、必要结构及审核后的片段。执行器补充常见key/value和Bearer脱敏，但此补充不能替代字段级脱敏。

事务资料使用`TransactionID/Direction/Method/Protocol/Destination/FieldNames`等实际解析值。`pair.RelatedIDs`精确引用请求与应答，并有相同事务及相反方向。解码材料使用`DecodeSteps`引用输入/输出，最多3步，只支持base64、无padding的base64url和hex；每一步都实际解码比较，最后一项必须是decoded_payload。可逆编码不是匿名化，编码输入及中间字节不发送LLM，改送本地验证说明；模型只解释脱敏明文。group_member携带实际AssetID/Role；history携带独立EventID、AdjudicationID、AdjudicationSource及审核误报标记。

将原始事实结果送入语义适配器前，需要按subject划分scope与分析窗口；不允许拿全事件统计或跨事务记录补齐某个命题的前提。事实的外部查询、群体核验和历史定谳可信度仍由事实模块及上游适配器负责，语义模块不重新构建这些数据。

## 上下文与结果校验

默认每次最多8项任务、总输入12000 UTF-8字节（含system prompt）、单段材料512字节、模型输出2000 token、返回16000字节、超时60秒。每项只包含所需事实ID/状态/来源及实际送达片段；不发送59项完整目录、全部原始命中或全部Finding。达到预算按整项跳过，不留下引用已省略材料的任务。每次最多调用一次，不自动重试或补调，以限制资源消耗。

字节数不是token数。生产部署应注入实际`CountTokens`并设置`MaxInputTokens`，从模型窗口中预留输出token、消息封装开销及其他上下文；不能把12000字节当成12000 token。所注入的计数函数接收完整system和user文本，应计入所使用模型的消息封装开销。

返回必须是单个严格JSON对象，拒绝Markdown、未知字段、重复JSON键、额外根对象、过深嵌套及超出长度限制的结果。未知task_id拒绝整批；重复task结果拒绝该任务；没返回的任务保持不可用。每项必须引用全部实际送达materials/facts，历史任务还须引用全部定谳ID；主要材料必须有非空逐字摘录，不能用方向或pair说明替代载荷/请求正文。scope、快照、窗口、规则版本均由程序补入，模型不能修改。

完整任务、来源版本、预算快照、脱敏原文SHA256、实际上下文SHA256、模型回答SHA256和执行原因可在本地持久化；模型名称及部署配置由调用方另行记录。SHA256仅用于追溯，不证明数据真实；编码材料的hash对应本地脱敏原文，送达文本为验证说明。`NonAdditiveWith`提示已成立的同命题事实不得重复计入；`DuplicateOf`标记同scope/window/PropositionID的重复阳性解释并保留审计内容，较强者优先，同强度按任务顺序选择。反证及解释专用结果保留，不因去重隐藏。

## 实现进度

已完成模块实现、23槽位的合成测试、关键边界测试及客户端HTTP契约测试。仍需在报告服务中构建可信快照适配器、配置真实tokenizer、落库及输出精简报告上下文，并进行真实告警回放/模型验收。现有报告服务尚未自动调用这23个槽位，旧版YAML和Python PoC的实现标记不代表本次Go后端进度。
