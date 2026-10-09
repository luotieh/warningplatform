package evidence

// Canonical fact definitions copied from evidence-library v0.1; not an LLM prompt.
type Definition struct {
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
	{ID: FactID("F_NXDOMAIN_CLUSTER"), Description: "NXDOMAIN 聚集（scope=asset，单资产）", Algorithm: "单资产窗口内不同 eTLD+1 的 NXDOMAIN >p99 基线；需 rcode＋未命中 DNS 分母"},
	{ID: FactID("F_GROUP_NXDOMAIN_CLUSTER"), Description: "群体 NXDOMAIN 聚集（scope=asset_group）", Algorithm: "≥3 资产同窗口对同词形簇域名的失败解析率 >群体基线 p99；需 rcode＋未命中分母；与单资产版为不同 fact"},
	{ID: FactID("F_FAILED_TO_ACTIVE"), Description: "失败域→激活连接", Algorithm: "连续失败域名中成功解析，且 ≤5min 外联对应 IP（DNS→连接关联）"},
	{ID: FactID("F_SHARED_DOMAIN_CLUSTER"), Description: "群体共同域名簇", Algorithm: "≥3 资产共同查询一簇非常规域名（同注册域/同命名模式）"},
	{ID: FactID("F_HTTP_ENDPOINT_REPEAT"), Description: "端点重复回连", Algorithm: "主机＋规范端点分组：重复 ≥6 次且间隔低抖动（CV≤0.3）；POST 本身不加分"},
	{ID: FactID("F_HTTP_FIELD_ENCODING"), Description: "字段编码异常", Algorithm: "编码链验证后异常长度/编码占比 >同服务基线 p95；排除 JWT/OAuth"},
	{ID: FactID("F_HTTP_UA_RARITY"), Description: "UA 稀有/不一致", Algorithm: "同资产 UA 一致且全平台稀有度 <p01；弱证据，与 S03 同事实取其一"},
	{ID: FactID("F_HTTP_SIZE_STABILITY"), Description: "请求/响应尺寸稳定", Algorithm: "n≥12；CV(size)<baseline_p05 且 unique_size_ratio<baseline_p05（或 z≤−2.0）"},
	{ID: FactID("F_LONG_LOW_SESSION"), Description: "长会话低频小流量", Algorithm: "会话 >30min 且双向 <10KB 且含周期小包（体量须 Q02 verified）"},
	{ID: FactID("F_URL_ODD_AUTHORITY"), Description: "URL 授权部分异常（弱欺骗）", Algorithm: "userinfo `@` / IP·数字·十六进制主机；deception_strength: weak，不满足 Phishing 欺骗门槛"},
	{ID: FactID("F_URL_HOMOGLYPH"), Description: "同形混淆字符（强欺骗）", Algorithm: "IDNA 解码后视觉近似（rn→m、0→o、西里尔/希腊字母混入）；输出混淆字符清单"},
	{ID: FactID("F_URL_BRAND_SUBDOMAIN_TRICK"), Description: "伪装子域（强欺骗）", Algorithm: "品牌词在子域而注册域无关（PSL 提取），如 `brand.com.evil.tld`"},
	{ID: FactID("F_BRAND_IMPOSTOR"), Description: "品牌仿冒", Algorithm: "与审核品牌清单编辑距离/邻键比对，或授权域核验失败；需品牌清单"},
	{ID: FactID("F_CRED_POST_STRUCTURE"), Description: "登录提交结构", Algorithm: "同请求 POST＋脱敏凭据字段名；正文截断标 insufficient"},
	{ID: FactID("F_FORM_CROSSSITE"), Description: "表单跨站提交", Algorithm: "action 与页面来源不同可注册域"},
	{ID: FactID("F_REDIRECT_CHAIN"), Description: "落地页→异站提交链", Algorithm: "事务 ID 关联的跨注册域跳转提交链；两条无关联命中不得拼接"},
	{ID: FactID("F_MULTI_REDIRECT_CHAIN"), Description: "多重短链跳转", Algorithm: "短链→中间页→落地页的重定向序列还原（需完整响应/Location）"},
	{ID: FactID("F_PROTOCOL_PORT_MISMATCH"), Description: "协议-端口错配", Algorithm: "dst_port vs 可解析 app_proto 指纹＋服务清单不符（端口推断的 protocol 不算）"},
	{ID: FactID("F_RARE_PORT"), Description: "稀有端口", Algorithm: "目的端口在同角色资产群体中频率 <p01"},
	{ID: FactID("F_DST_NOVELTY"), Description: "目的端点新颖", Algorithm: "资产历史覆盖窗口内首现（只称\"首次告警\"）"},
	{ID: FactID("F_INFRA_RARITY"), Description: "目标基础设施稀有度", Algorithm: "目的 IP 的 ASN/地理/信誉稀有（外部清单，二期）"},
	{ID: FactID("F_FANOUT_SINGLE_SRC"), Description: "单源目标扇出", Algorithm: "跨事件按源去重 unique(dst,port)/小时 >角色基线 p99"},
	{ID: FactID("F_PORT_SEQUENCE"), Description: "端口序列形态", Algorithm: "目的端口序列呈顺序/逆序/伪随机（≥8 去重端口）"},
	{ID: FactID("F_SMALL_PACKET"), Description: "小包无载荷", Algorithm: "payload 长度分布 ≥80% 集中于小包"},
	{ID: FactID("F_CONN_FAIL_RATE"), Description: "连接失败率", Algorithm: "SYN/RST 失败比例 >p95（需 TCP 状态，一期仅线索）"},
	{ID: FactID("F_INDEPENDENT_RULE_CORROB"), Description: "独立规则交叉佐证", Algorithm: "by_rule＋规则库元数据判独立性；同 IOC 派生多 rule_id 只记一组"},
	{ID: FactID("F_INDEPENDENT_INTEL_CORROB"), Description: "跨情报源独立命中", Algorithm: "多情报源/引擎独立标记同一目的；须验证情报源独立性（同源转引不算）"},
	{ID: FactID("F_IOC_TYPE_CORROB"), Description: "IOC 类型与行为证据一致", Algorithm: "IOC 情报类型与成立硬行为事实类型一致（evaluation_stage=post_hard_type；抑制与 modifier 后的 hard_type_scores 满足 top1≥15、份额≥0.60、margin≥10 且情报标签与 top1 一致时成立）；不回填类型分"},
	{ID: FactID("F_TLS_SNI_MISMATCH"), Description: "SNI 与目的不符", Algorithm: "需 TLS 握手元数据；CDN 例外清单"},
	{ID: FactID("F_TLS_CERT_ANOMALY"), Description: "自签名/异常证书", Algorithm: "证书链/有效期/颁发者异常"},
	{ID: FactID("F_TLS_JA_MISMATCH"), Description: "JA3/JA4 指纹与声明不符", Algorithm: "指纹库比对；浏览器声称 vs TLS 指纹"},
	{ID: FactID("F_MULTI_ASSET_IOC"), Description: "多资产同 IOC", Algorithm: "≥3 独立资产（NAT/代理/解析器归属去重）同 IOC 且时间聚集"},
	{ID: FactID("F_MULTI_ASSET_DIST"), Description: "聚集分布形态", Algorithm: "命中资产跨网段随机分布（真感染面）vs 同网段管理面"},
	{ID: FactID("F_TIME_COORDINATION"), Description: "多资产时间协同", Algorithm: "各资产到同端点时序相位一致（互相关 >0.7），或秒级窗口同向突发"},
	{ID: FactID("F_COORD_FANOUT"), Description: "协同扫描/扇出", Algorithm: "多源目标集合重叠 >70%，或不同资产分工覆盖目标段且时间衔接"},
	{ID: FactID("F_INFECTION_CHAIN"), Description: "感染链传播", Algorithm: "A 可疑外联→A 访问多内网 B→B 随后外联同目的的时序链"},
	{ID: FactID("F_SHARED_ENDPOINT"), Description: "共享目的端点", Algorithm: "去 IOC 标签后 ≥3 资产独立聚集同目的端点（端点稀有度 × 资产数）"},
	{ID: FactID("F_FIRST_VISIT_CLUSTER"), Description: "首访时间聚集", Algorithm: "多资产首访集中 ≤1h 窗口（投递后点击潮）"},
	{ID: FactID("F_COORD_PATTERN_RECURRENCE"), Description: "协同模式跨日重复", Algorithm: "同一资产组的协同模式（相位/突发窗口）在 ≥2 个自然日重现"},
	{ID: FactID("F_HIST_ASSET_IOC_RECURRENCE"), Description: "同 IOC→同资产跨日复发", Algorithm: "30 天窗 ≥2 自然日独立事件；确认恶意 +20｜判误报 −20｜未审核 0"},
	{ID: FactID("F_HIST_GROUP_RECURRENCE"), Description: "群体+基础设施复发", Algorithm: "同 IOC 簇/同族域名/同目的端点的资产组跨周重现；确认恶意 +15｜判误报 −15｜未审核 0"},
	{ID: FactID("F_HIST_INFRA_PERSISTENCE"), Description: "钓鱼基础设施持续存活", Algorithm: "同 IOC 连续多天被不同资产访问；确认恶意 +15｜未审核 0"},
	{ID: FactID("F_HIST_SCHEDULE_MATCH"), Description: "历史时刻模式一致", Algorithm: "历史事件与当前命中时刻分布一致（KL 散度 <阈值）"},
	{ID: FactID("F_HIST_MULTI_IOC_SIEGE"), Description: "同资产多 IOC 围攻", Algorithm: "窗口内同资产被 ≥3 不同 IOC/规则族命中；按角色基线"},
	{ID: FactID("F_HIST_STAGE_PROGRESSION"), Description: "攻击阶段递进", Algorithm: "同资产、同IOC或独立核验战役内，已定谳恶意历史与有来源证明的CurrentStage构成scan/exploit→c2→exfil推进；当前阶段须高于最近历史阶段，历史不得回退；不证明因果攻击链"},
	{ID: FactID("F_HIST_COORD_PARAM_MATCH"), Description: "历史协同参数一致", Algorithm: "同实际基础设施、独立核验战役及资产/完整群体范围内，核验的当前协同参数与已定谳历史按配置容限比较；群体ID及完整核验成员集合须一致；只说明受约束的参数相似"},
	{ID: FactID("F_HIST_EXERCISE"), Description: "登记演练平台命中", Algorithm: "资产/域名属登记钓鱼演练或测试平台（留验证记录）；classification_effect: type=PH, effective_score_cap=34, status=candidate"},
	{ID: FactID("F_IOC_NOVELTY"), Description: "IOC 平台首现", Algorithm: "历史库无记录；与 F_HIST_ASSET_IOC_RECURRENCE 互斥"},
	{ID: FactID("F_EXCL_SCAN_TASK"), Description: "已核验扫描任务", Algorithm: "核验登记角色/任务与当前活动匹配，不由模型推断"},
	{ID: FactID("F_EXCL_INFRA_ROLE"), Description: "已核验基础服务", Algorithm: "核验登记角色/任务与当前活动匹配，不由模型推断"},
}

func Definitions() []Definition { return append([]Definition(nil), definitions...) }
func SupportedFacts() []FactID {
	ids := make([]FactID, len(definitions))
	for i, d := range definitions {
		ids[i] = d.ID
	}
	return ids
}
