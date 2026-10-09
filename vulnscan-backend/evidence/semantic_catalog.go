package evidence

type slotSpec struct {
	SemanticDefinition
	Kinds    []string
	AllFacts []FactID
	AnyFacts []FactID
}

func semanticSpec(id, target, subtype, prerequisite, dedupe string, explanation bool, kinds []string, all, any []FactID) slotSpec {
	return slotSpec{SemanticDefinition{SlotKey{id, target, subtype}, prerequisite, explanation, dedupe}, kinds, all, any}
}

// Runtime registry is intentionally independent of the legacy draft YAML flags.
var semanticSpecs = []slotSpec{
	semanticSpec("S01", "c2.command_intent", "", "可读协议、可信方向；strong须同事务双向语义对应；不证明执行成功", "command", false, []string{"protocol_request", "direction"}, nil, nil),
	semanticSpec("S02", "c2.command_exchange", "", "同事务真实请求应答；排除文档与日志回显", "command", false, []string{"protocol_request", "protocol_response", "pair"}, nil, nil),
	semanticSpec("S03", "c2.ua_behavior_conflict", "", "重复端点事实及实际UA；浏览器声明不足", "ua", false, []string{"ua", "protocol_request"}, []FactID{"F_HTTP_ENDPOINT_REPEAT"}, nil),
	semanticSpec("S04", "c2.dns_encoded_intent", "", "编码标签事实及代码验证解码链；考虑追踪token", "payload", false, []string{"domain", "decode", "decoded_payload"}, []FactID{"F_DNS_ENCODED_LABEL"}, nil),
	semanticSpec("S05", "phishing.deception", "", "页面正文、Host、核验品牌授权域；strong须明确仿冒依据", "deception", false, []string{"page", "host", "brand_authorization"}, nil, nil),
	semanticSpec("S06", "phishing.credential_action", "", "同请求字段名、方法、目的及行动事实；只解释收集意图", "credential", false, []string{"credential_fields", "protocol_request"}, nil, []FactID{"F_CRED_POST_STRUCTURE", "F_FORM_CROSSSITE", "F_REDIRECT_CHAIN"}),
	semanticSpec("S07", "exfil.sensitive_upload", "", "完整请求、可信方向与体量、内容分类依据；不证明送达", "transfer", false, []string{"protocol_request", "direction", "volume", "content_classification"}, nil, nil),
	semanticSpec("S08", "exfil.chunk_sequence", "", "至少两个可靠关联事务、块序号及可信体量；禁止拼接无关命中", "transfer", false, []string{"chunk", "volume", "transfer_join"}, nil, nil),
	semanticSpec("S09", "exploit.payload_intent", "", "已解析请求载荷、方法、目标协议及可信方向；不证明利用成功", "payload", false, []string{"protocol_request", "parsed_payload", "direction"}, nil, nil),
	semanticSpec("S10", "protocol.response_meaning", "", "同事务真实双向应答；HTTP200不证明执行", "command", false, []string{"protocol_request", "protocol_response", "pair"}, nil, nil),
	semanticSpec("S11", "mining.protocol_intent", "", "实际Stratum方法、参数和应答；不重复协议事实", "mining", false, []string{"stratum_request", "stratum_response", "pair"}, nil, nil),
	semanticSpec("S12", "c2.domain_lexical", "dga_lexical", "原始域名及词形上下文；随机串不自动等于DGA", "domain", false, []string{"domain", "lexical_context"}, nil, nil),
	semanticSpec("S12", "phishing.deception", "brand_semantic_impostor", "品牌、实际授权域与仿冒关系；仅品牌词最多weak", "deception", false, []string{"brand", "host", "brand_authorization"}, nil, nil),
	semanticSpec("S13", "payload.decoded_intent", "command", "代码验证解码链及实际命令上下文；strong遵循S01", "command", false, []string{"decode", "decoded_payload", "protocol_request", "direction"}, nil, nil),
	semanticSpec("S13", "payload.decoded_intent", "other", "代码验证解码链及独立操作上下文；解码成功不等于恶意", "payload", false, []string{"decode", "decoded_payload", "operation_context"}, nil, nil),
	semanticSpec("S14", "review.benign_alternative", "", "实际流量、事实规则、资产角色及任务上下文；仅记录异议", "", true, []string{"protocol_request", "asset_role", "task_context"}, nil, nil),
	semanticSpec("S15", "review.stage_and_gaps", "", "接受的事实、可见范围及缺项；成功性须独立证据", "", true, []string{"visibility", "gaps"}, nil, nil),
	semanticSpec("BT-S01", "botnet.coordination", "", "核验群体及协同硬事实；最多5资产；不替代硬门槛", "coordination", false, []string{"group_member"}, nil, []FactID{"F_TIME_COORDINATION", "F_COORD_PATTERN_RECURRENCE", "F_COORD_FANOUT", "F_INFECTION_CHAIN"}),
	semanticSpec("SC01", "c2.role_schedule_conflict", "", "核验角色、业务作息及实际时间分布；夜间服务器运行不自动异常", "schedule", false, []string{"asset_role", "business_schedule", "time_distribution"}, nil, nil),
	semanticSpec("SC02", "botnet.group_alternative", "", "核验群体角色与实际行为摘要；供人工解释", "", true, []string{"group_member"}, nil, nil),
	semanticSpec("SC03", "phishing.brand_field_conflict", "", "实际品牌、字段级引用及核验授权背景；不替代欺骗或行动门槛", "brand_field", false, []string{"brand", "credential_fields", "brand_authorization"}, nil, nil),
	semanticSpec("R06", "history.same_campaign", "", "最多5条独立定谳历史及当前模式；必须引用定谳ID", "", true, []string{"history", "current_pattern"}, nil, nil),
	semanticSpec("R07", "history.false_positive_match", "", "审核误报历史及实际当前模式；模型不能扣分", "", true, []string{"history", "current_pattern"}, nil, nil),
}

func SemanticDefinitions() []SemanticDefinition {
	out := make([]SemanticDefinition, len(semanticSpecs))
	for i, s := range semanticSpecs {
		out[i] = s.SemanticDefinition
	}
	return out
}
