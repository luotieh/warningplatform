package evidence

// Executable feature contracts. Stable IDs do not imply an attack verdict.
type Definition struct {
	EvidenceContract
	ID          FactID `json:"fact_id"`
	Description string `json:"description"`
	Algorithm   string `json:"algorithm"`
}

var definitions = []Definition{
	{ID: FactID("F_BEACON_PERIODIC"), Description: "严格周期信标", Algorithm: "n≥8；5s≤Δt≤24h；CV(Δt)≤0.15；每次≤5 包（DetectHeartbeat）"},
	{ID: FactID("F_BEACON_JITTER"), Description: "抖动周期信标", Algorithm: "n≥16；median(Δt) 稳定且 0.15<CV≤0.40；Ljung-Box p<0.05 且 ACF 峰值>0.3"},
	{ID: FactID("F_FIXED_DAILY_WINDOW"), Description: "每天固定时间点", Algorithm: "≥3 自然日且 ≥80% 命中落在同一 ≤2h 窗口"},
	{ID: FactID("F_MULTI_DAY_PERSIST"), Description: "跨日持续", Algorithm: "锁定窗口内逐日桶活跃 ≥2 天为 days2 / ≥3 天为 days3（不用首末两点推持续；固定资产/端点，需跨段时联合快照）"},
	{ID: FactID("F_RATE_BURST"), Description: "命中突发", Algorithm: "peak_window(5m)/长期窗口均值 >p99 基线"},
	{ID: FactID("F_RATE_RAMP"), Description: "速率阶梯上升", Algorithm: "至少5个固定等长窗口；无并列值时精确双侧Mann-Kendall p<0.05；并列/缺窗标ineligible，禁止静默切渐近检验"},
	{ID: FactID("F_DNS_HIGH_ENTROPY"), Description: "长标签高基数子域（单资产）", Algorithm: "PSL 归一后：独特子域比 >p95 且 标签长 p90 >p95 且 查询速率 >p95（同域基线）；单机高熵不支持 Botnet"},
	{ID: FactID("F_DNS_ENCODED_LABEL"), Description: "子域编码结构", Algorithm: "base32/hex 模式匹配且代码可验证解码链"},
	{ID: FactID("F_DGA_LEXICAL"), Description: "词形随机性（单资产）", Algorithm: "bigram 对数概率 <语料 p05；元音比/长度分布异常；单机随机域名不支持 Botnet"},
	{ID: FactID("F_NXDOMAIN_CLUSTER"), Description: "NXDOMAIN失败率与多注册域聚集（单资产）", Algorithm: "单资产完整查询窗口内 NXDOMAIN 查询比例 > nxdomain_rate_p99，且失败的不同 eTLD+1 ≥2；基线单位为查询比例"},
	{ID: FactID("F_GROUP_NXDOMAIN_CLUSTER"), Description: "群体 NXDOMAIN 聚集（scope=asset_group）", Algorithm: "≥3 资产同窗口对同词形簇域名的失败解析率 >群体基线 p99；需 rcode＋未命中分母；与单资产版为不同 fact"},
	{ID: FactID("F_FAILED_TO_ACTIVE"), Description: "失败域→激活连接", Algorithm: "同一规范DNS问题名至少min_failures次先前NXDOMAIN，随后NOERROR回答IP且同资产≤5min连接该IP；不要求连续失败"},
	{ID: FactID("F_SHARED_DOMAIN_CLUSTER"), Description: "群体共同域名簇", Algorithm: "≥3 资产共同查询一簇非常规域名（同注册域/同命名模式）"},
	{ID: FactID("F_HTTP_ENDPOINT_REPEAT"), Description: "端点重复回连", Algorithm: "主机＋规范端点分组：重复 ≥6 次且间隔低抖动（CV≤0.3）；POST 本身不加分"},
	{ID: FactID("F_HTTP_FIELD_ENCODING"), Description: "字段编码异常", Algorithm: "编码链验证后异常长度/编码占比 >同服务基线 p95；排除 JWT/OAuth"},
	{ID: FactID("F_HTTP_UA_RARITY"), Description: "UA一致且稀有", Algorithm: "同资产 UA 一致且全平台稀有度 <p01；弱证据，与 S03 同事实取其一"},
	{ID: FactID("F_HTTP_SIZE_STABILITY"), Description: "HTTP请求体大小稳定", Algorithm: "n≥12；仅请求BodyLength：CV< size_cv_p05 且 unique_size_ratio<unique_size_ratio_p05；不计算响应或z分数"},
	{ID: FactID("F_LONG_LOW_SESSION"), Description: "长会话低频小流量", Algorithm: "会话 >30min 且双向 <10KB 且含周期小包（体量须 Q02 verified）"},
	{ID: FactID("F_URL_ODD_AUTHORITY"), Description: "URL 授权部分异常（弱欺骗）", Algorithm: "userinfo `@` / IP·数字·十六进制主机；deception_strength: weak，不满足 Phishing 欺骗门槛"},
	{ID: FactID("F_URL_HOMOGLYPH"), Description: "域名有限字符映射近似", Algorithm: "有限字符映射后与核验品牌域近似；不覆盖完整Unicode视觉混淆检测"},
	{ID: FactID("F_URL_BRAND_SUBDOMAIN_TRICK"), Description: "子域品牌词与授权注册域冲突", Algorithm: "品牌词在子域而注册域无关（PSL 提取），如 `brand.com.evil.tld`"},
	{ID: FactID("F_BRAND_IMPOSTOR"), Description: "品牌仿冒", Algorithm: "与审核品牌清单编辑距离/邻键比对，或授权域核验失败；需品牌清单"},
	{ID: FactID("F_CRED_POST_STRUCTURE"), Description: "登录提交结构", Algorithm: "同请求 POST＋脱敏凭据字段名；正文截断标 insufficient"},
	{ID: FactID("F_FORM_CROSSSITE"), Description: "表单跨站提交", Algorithm: "action 与页面来源不同可注册域"},
	{ID: FactID("F_REDIRECT_CHAIN"), Description: "落地页→异站提交链", Algorithm: "事务 ID 关联的跨注册域跳转提交链；两条无关联命中不得拼接"},
	{ID: FactID("F_MULTI_REDIRECT_CHAIN"), Description: "多次HTTP重定向", Algorithm: "同一已关联会话内≥2条经RedirectVerified验证的事务跳转边；核验响应状态及Location，不识别短链服务"},
	{ID: FactID("F_PROTOCOL_PORT_MISMATCH"), Description: "协议-端口错配", Algorithm: "dst_port vs 可解析 app_proto 指纹＋服务清单不符（端口推断的 protocol 不算）"},
	{ID: FactID("F_RARE_PORT"), Description: "稀有端口", Algorithm: "目的端口在同角色资产群体中频率 <p01"},
	{ID: FactID("F_DST_NOVELTY"), Description: "目的端点新颖", Algorithm: "资产历史覆盖窗口内首现（只称\"首次告警\"）"},
	{ID: FactID("F_INFRA_RARITY"), Description: "目标基础设施稀有度", Algorithm: "目的 IP 的 ASN/地理/信誉稀有（外部清单，二期）"},
	{ID: FactID("F_FANOUT_SINGLE_SRC"), Description: "单源目标扇出", Algorithm: "跨事件按源去重 unique(dst,port)/小时 >角色基线 p99"},
	{ID: FactID("F_PORT_SEQUENCE"), Description: "端口序列形态", Algorithm: "目的端口序列呈顺序/逆序/伪随机（≥8 去重端口）"},
	{ID: FactID("F_SMALL_PACKET"), Description: "低应用载荷占比", Algorithm: "≥80%独立连接观测的应用载荷字节数≤small_payload_bytes；另记录零载荷比例，不等同零载荷"},
	{ID: FactID("F_CONN_FAIL_RATE"), Description: "连接失败率", Algorithm: "完整窗口确认失败/(确认失败+确认成功)>connection_failure_rate_p95；须OutcomeVerified；尝试中或未知结局返回missing，SYN_SENT不计失败"},
	{ID: FactID("F_INDEPENDENT_RULE_CORROB"), Description: "独立规则交叉佐证", Algorithm: "by_rule＋规则库元数据判独立性；同 IOC 派生多 rule_id 只记一组"},
	{ID: FactID("F_INDEPENDENT_INTEL_CORROB"), Description: "跨情报源独立命中", Algorithm: "多情报源/引擎独立标记同一目的；须验证情报源独立性（同源转引不算）"},
	{ID: FactID("F_IOC_TYPE_CORROB"), Description: "IOC 类型与行为证据一致", Algorithm: "IOC 情报类型与成立硬行为事实类型一致（evaluation_stage=post_hard_type；抑制与 modifier 后的 hard_type_scores 满足 top1≥15、份额≥0.60、margin≥10 且情报标签与 top1 一致时成立）；不回填类型分"},
	{ID: FactID("F_TLS_SNI_MISMATCH"), Description: "SNI与证书名称不符", Algorithm: "已核验TLS握手SNI与证书名称匹配失败；需已核验CDN例外清单；不比较目的服务身份"},
	{ID: FactID("F_TLS_CERT_ANOMALY"), Description: "自签名/异常证书", Algorithm: "证书链/有效期/颁发者异常"},
	{ID: FactID("F_TLS_JA_MISMATCH"), Description: "JA3/JA4 指纹与声明不符", Algorithm: "指纹库比对；浏览器声称 vs TLS 指纹"},
	{ID: FactID("F_MULTI_ASSET_IOC"), Description: "多资产同 IOC", Algorithm: "≥3 独立资产（NAT/代理/解析器归属去重）同 IOC 且时间聚集"},
	{ID: FactID("F_MULTI_ASSET_DIST"), Description: "聚集分布形态", Algorithm: "核验成员的子网熵及角色分布达到配置门槛；不推断随机感染或真实感染面"},
	{ID: FactID("F_TIME_COORDINATION"), Description: "多资产时间协同", Algorithm: "≥3资产到同一协议/IP/端口的有界时间桶序列；最小两两互相关>0.7；Endpoint缺失不执行"},
	{ID: FactID("F_COORD_FANOUT"), Description: "多资产目标集合重叠或扇出衔接", Algorithm: "多源目标集合重叠 >70%，或不同资产分工覆盖目标段且时间衔接"},
	{ID: FactID("F_INFECTION_CHAIN"), Description: "疑似横向传播时序", Algorithm: "A外联同一协议/IP/端口→A访问另一成员B的核验地址→B随后外联该端点；至少一条时序路径，不证明感染或利用成功"},
	{ID: FactID("F_SHARED_ENDPOINT"), Description: "共享目的端点", Algorithm: "≥3核验资产连接同一协议/IP/端口，且endpoint_frequency<endpoint_frequency_p01；DNS查询不充当连接"},
	{ID: FactID("F_FIRST_VISIT_CLUSTER"), Description: "首次已保存访问时间聚集", Algorithm: "完整历史窗口内无先前记录的同端点访问，≥3资产集中≤1h；不证明网络真实首访或点击"},
	{ID: FactID("F_COORD_PATTERN_RECURRENCE"), Description: "协同模式跨日重复", Algorithm: "同一资产组的协同模式（相位/突发窗口）在 ≥2 个自然日重现"},
	{ID: FactID("F_HIST_ASSET_IOC_RECURRENCE"), Description: "同 IOC→同资产跨日复发", Algorithm: "30天窗≥2自然日独立事件；允许有来源的partial阳性；F不按审核状态计分，C01按一期联合策略计分"},
	{ID: FactID("F_HIST_GROUP_RECURRENCE"), Description: "群体+基础设施复发", Algorithm: "同已核验群体及基础设施跨周重现；仅输出历史事实，不执行旧版审核加减分"},
	{ID: FactID("F_HIST_INFRA_PERSISTENCE"), Description: "连续跨日多资产IOC关联", Algorithm: "同IOC连续自然日由多个资产产生已保存历史记录；只输出关联事实，不证明服务存活、钓鱼或直接加分"},
	{ID: FactID("F_HIST_SCHEDULE_MATCH"), Description: "历史时刻模式一致", Algorithm: "历史事件与当前命中时刻分布一致（KL 散度 <阈值）"},
	{ID: FactID("F_HIST_MULTI_IOC_SIEGE"), Description: "同资产多 IOC 围攻", Algorithm: "窗口内同资产被 ≥3 不同 IOC/规则族命中；按角色基线"},
	{ID: FactID("F_HIST_STAGE_PROGRESSION"), Description: "攻击阶段递进", Algorithm: "同资产、同IOC或独立核验战役内，已定谳恶意历史与有来源证明的CurrentStage构成scan/exploit→c2→exfil推进；当前阶段须高于最近历史阶段，历史不得回退；不证明因果攻击链"},
	{ID: FactID("F_HIST_COORD_PARAM_MATCH"), Description: "历史协同参数一致", Algorithm: "同实际基础设施、独立核验战役及资产/完整群体范围内，核验的当前协同参数与已定谳历史按配置容限比较；群体ID及完整核验成员集合须一致；只说明受约束的参数相似"},
	{ID: FactID("F_HIST_EXERCISE"), Description: "登记演练平台命中", Algorithm: "资产/域名属登记钓鱼演练或测试平台（留验证记录）；classification_effect: type=PH, effective_score_cap=34, status=candidate"},
	{ID: FactID("F_IOC_NOVELTY"), Description: "IOC 平台首现", Algorithm: "历史库无记录；与 F_HIST_ASSET_IOC_RECURRENCE 互斥"},
	{ID: FactID("F_EXCL_SCAN_TASK"), Description: "已核验扫描任务", Algorithm: "核验登记角色/任务与当前活动匹配，不由模型推断"},
	{ID: FactID("F_EXCL_INFRA_ROLE"), Description: "已核验基础服务", Algorithm: "核验登记角色/任务与当前活动匹配，不由模型推断"},
}

func Definitions() []Definition {
	out := append([]Definition(nil), definitions...)
	for i := range out {
		out[i].EvidenceContract = factContract(out[i])
	}
	return out
}
func SupportedFacts() []FactID {
	ids := make([]FactID, len(definitions))
	for i, d := range definitions {
		ids[i] = d.ID
	}
	return ids
}
