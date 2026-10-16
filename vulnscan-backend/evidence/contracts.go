package evidence

const ContractVersion = "evidence-contracts-1"

// EvidenceContract separates what the program measures from a security
// interpretation. Neither a feature nor a model quotation confirms an outcome.
type EvidenceContract struct {
	FeatureClaim           string   `json:"feature_claim"`
	SecurityInterpretation string   `json:"security_interpretation"`
	CannotProve            string   `json:"cannot_prove"`
	RequiredCorrelations   []string `json:"required_correlations"`
}

func contractForFact(id FactID) EvidenceContract {
	for _, d := range definitions {
		if d.ID == id {
			return factContract(d)
		}
	}
	return EvidenceContract{}
}

func factContract(d Definition) EvidenceContract {
	c := EvidenceContract{FeatureClaim: d.Algorithm,
		SecurityInterpretation: d.Description + "；仅作为已核验输入范围内的特征线索",
		CannotProve:            "不能单独证明恶意意图、攻击归属、主机感染或攻击成功",
		RequiredCorrelations:   []string{"同资产及真实通信来源绑定", "独立行为或内容证据及授权背景；仅适用的C联合规则决定风险贡献"}}
	switch d.ID {
	case BeaconPeriodic, "F_BEACON_JITTER", "F_HTTP_ENDPOINT_REPEAT":
		c.CannotProve = "周期或重复请求不证明C2；累计FLOW包数不能替代逐次独立联系"
		c.RequiredCorrelations = []string{"同资产、端点与IOC的原始字段绑定", "完整独立联系或HTTP事务观测", "适用的C02/C04前提；F_BEACON_PERIODIC不属于一期C"}
	case "F_FIXED_DAILY_WINDOW", MultiDayPersist:
		c.CannotProve = "活跃日期或日内集中不证明持续在线、持久化或恶意作息"
	case "F_DNS_HIGH_ENTROPY":
		c.CannotProve = "未计算Shannon熵；高唯一率、长标签与高查询率不证明隧道或Botnet"
	case "F_DNS_ENCODED_LABEL":
		c.CannotProve = "编码结构不证明恶意目的或数据外传"
		c.RequiredCorrelations = []string{"S04对同一DNS问题及程序验证解码链的语义解释", "C07同源关联及去重"}
	case "F_DGA_LEXICAL":
		c.CannotProve = "词形代理指标不证明DGA生成机制或家族归属"
	case "F_FAILED_TO_ACTIVE":
		c.CannotProve = "同问题名失败后解析并连接不证明域名激活原因、C2或感染"
	case "F_HTTP_SIZE_STABILITY":
		c.CannotProve = "只计算请求体大小；未证明响应大小稳定、回连目的或传输内容"
	case "F_MULTI_REDIRECT_CHAIN", "F_REDIRECT_CHAIN":
		c.CannotProve = "不识别短链服务，不证明钓鱼；SessionID只用于限制现有已核验链，不能猜测浏览器跨连接身份"
	case "F_SMALL_PACKET":
		c.CannotProve = "低应用载荷不等于零载荷，也不证明扫描或探测意图"
	case "F_CONN_FAIL_RATE":
		c.CannotProve = "连接尝试、单独RST或CLOSED状态不证明最终连接失败；失败比例不证明扫描"
	case "F_TLS_SNI_MISMATCH":
		c.CannotProve = "仅SNI与证书名称比较；不验证实际目的服务身份，不证明流量伪装"
	case "F_INFECTION_CHAIN":
		c.CannotProve = "A→B时间顺序不证明感染、利用成功或因果传播；一条路径不证明多个B"
		c.RequiredCorrelations = []string{"独立主机感染或执行证据", "每条边的真实资产、协议、目的IP和端口绑定"}
	case "F_HIST_INFRA_PERSISTENCE":
		c.CannotProve = "已保存跨日多资产IOC关联不证明服务持续存活或钓鱼活动"
	case "F_HIST_ASSET_IOC_RECURRENCE":
		c.CannotProve = "历史复发不证明恶意；不重复审核IOC；F不执行旧版审核加减分"
		c.RequiredCorrelations = []string{"同资产设备与IOC真实关系", "C01一期确定性联合策略；partial仅允许有来源的阳性"}
	}
	return c
}

func semanticContract(d SemanticDefinition) EvidenceContract {
	c := EvidenceContract{FeatureClaim: "在材料、引用、事务和前提结构验证后解释：" + d.Prerequisite,
		SecurityInterpretation: "模型对" + d.Key.Target + "的受约束解释；语义正确性须独立评价",
		CannotProve:            "引用存在与结构校验通过不等于恶意语义正确，也不证明执行、利用成功、感染或送达",
		RequiredCorrelations:   []string{"槽位要求的原始材料及事实前提", "确认行为结果须另有独立网络、主机或执行证据"}}
	if d.ExplanationOnly {
		c.SecurityInterpretation = "仅解释上下文、替代原因或缺项；不独立产生风险加减分"
	}
	return c
}
