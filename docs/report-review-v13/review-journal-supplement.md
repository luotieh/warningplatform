# 第一轮补交留档复核单：R1-IP117-006

评审人：/root/client_report_review（独立模拟甲方公安研判人员）。补交来源：实施者通知北京时间2026-10-12约02:25从180当前数据库只读收集，更新同目录source-journal.jsonl。本单仅核查报告1308与当前模型调用的ASCII身份/用量绑定，不修改review-second-case.md或review-first-case.md原始意见，不复验其他问题。

## 核查结果

原问题R1-IP117-006的**本次报告输入/用量留档缺失已通过补交解除**；ASCII身份绑定通过。以下字段完全一致：

| 记录 | 当前身份及数据 |
| --- | --- |
| report.json / report_document | event_id=ly-b2d8257f-4829-49aa-8a69-c7ebd3a4fdbb；summary_id=1308；analysis_version=3；report_document key=该event:1308；created_at=2026-10-11T18:15:26.329897261Z |
| 当前部署revision | 39a5a71ff11f6194938c12b1702866415fffd510，在report_document、correction_input和两次usage中一致 |
| 最终报告model_input_hash | e4e9e06afc5c5fa396ab73880a2404d39db88691fe60370bdd0da1cf82f16a76 |
| report_model_correction_input | key=该event:4:3；input_hash与最终报告hash一致；system/user字段存在，user_length=29999 |
| 最终report_model_usage | key=该event:4:3:2；input_hash与最终报告hash一致；model=K2.7；prompt_tokens=13876；completion_tokens=758；finish_reason=stop；capacity_verified=false |
| 初次report_model_usage | key=该event:4:3:1；input_hash=93aec9926cdc08bb61d41ffb57406eaaafafbc2698e8134d5feef9421526e644；同revision；model=K2.7；prompt_tokens=13037；completion_tokens=776；finish_reason=stop |
| report_model_input | key=该event:4:3；created_at=2026-10-11T18:15:00.244979659Z；snapshot_version=4；analysis_version=3；weight_policy.version=report-weights-1.3；no_floor=true；ordinary_relative_influence=1 |

结构化user字段可解析：schema_version=evidence-report-1.3、snapshot_version=4、selected_evidence数量10；history_lookup lookback_start=2026-09-09T03:53:42.628917Z、as_of=2026-10-09T03:53:42.628917Z、status=partial；report_weight_policy.version=report-weights-1.3。以上与固定证据范围一致。

最终报告绑定的是第二次、纠正输入调用；不能把第一次的输入hash或用量当最终输入。补交文件当前能提供两次调用的对应身份；本单不声称其存储机制已经保证历史不可变，也不把capacity_verified=false解释为容量已验证。

## 留档文本读取限制

提供方指出该补交源文件部分中文字符串存在乱码。本次UTF-8读取的所抽样中文权重句与correction_input开头可读，但没有逐字符串核验全量中文是否完整，亦未重新计算包含中文的hash来作字节级验证。因此本单确认的是日志声明的ASCII hash/revision/report_id与用量一致，以及输入字段存在；**不等于全量中文模型输入语义/原文保真核验完成**。完整文本内容核验及乱码修复仍须可靠的原始编码/字节留档，不得用可读片段推定整个输入无损。

## 闭环状态

R1-IP117-006中“缺本次report_id/input_hash/revision及用量绑定”的缺交事实可记录为补交已解决；其完整文本核查受上述读取限制，不声称已经全面通过。其他R1-IP117-001—005、007及首例问题未复验、未关闭。报告1308总体仍为不通过；本次补交不是新报告，不计第二轮评审。后续系统修复、180重新生成与独立复验仍须执行。

## 追加：原始UTF-8留档复核

新增补交文件source-journal-raw-utf8.jsonl及journal-utf8-validation.json。实施者说明此前显示异常来自Windows Python默认GBK标准输出被工具按UTF-8解释，而非数据库文件损坏；本次以mysql HEX提取value_json并严格UTF-8解码。本评审使用Get-Content -Encoding UTF8读取和JSON解析复核，未修改前述原意见。

独立对比原始journal中的report_document.markdown与既有API report.json的markdown：summary_id=1307、1308均逐字符完全相同，U+FFFD替换字符数量均为0；此结果与validation文件一致。1308的correction_input、report_document和最终usage的hash e4e9e06afc5c5fa396ab73880a2404d39db88691fe60370bdd0da1cf82f16a76及revision 39a5a71ff11f6194938c12b1702866415fffd510再次一致，记录字符串检查替换字符为0。

最终correction_input中文系统提示与正文可读；user是首行结构化JSON加后续中文纠正指令/上次输出，不能将整个user误当单一JSON解析。首行可解析并送达E001—E010十项证据和report-weights-1.3；后续指令明确上次失败原因为report_fact_numbers_not_in_cited_scope: value=104.21.57.117 refs=E008，要求纠正引用、同源重复和不支持结论，且不得提高概率。本次可读取这些真实输入文字，前述“中文留档读取限制”已解除，不再作为缺交保留。

据此R1-IP117-006关闭（补交材料关闭，关闭人/root/client_report_review）。这是输入/用量可追溯问题的关闭，并非承认模型推理正确，也不是再次评审报告质量。其他所有首轮实质问题仍待系统修复后新报告复验。

状态说明：实施者通知180已部署b7c4032，但模型上游403七日额度耗尽，当前未取得可评审的第二轮合格新报告。本评审未用旧1307/1308计算第二轮，未认可当前系统问题已修复；第一轮批次及至少两轮闭环仍未完成。
