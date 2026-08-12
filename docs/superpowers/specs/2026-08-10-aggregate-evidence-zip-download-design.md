# 聚合事件全量 PCAP 打包下载设计（Aggregate Evidence ZIP）

- 日期: 2026-08-10
- 状态: 已确认，已实施，待部署验证
- 来源契约: `docs/event-push-api.md` §3.8（`evidence_files`）、§5.4（节点证据下载接口）
- 前置实施: `docs/superpowers/specs/2026-08-10-evidence-pcap-source-adaptation-design.md`

## 1. 背景与现状

融合采集节点（ta_node）每次规则命中都会推送一条事件，且每条命中都携带
`evidence_files`（触发包 PCAP 已在节点落档，管理端可通过
`GET http://<node>:25640/api/v1/evidence/<path_ref>` 代理取回）。

管理端按 `src_ip + dst_ip + event_type` 做聚合（SHA256 指纹），当前聚合逻辑：

- 首次命中：`LyEventToDeepSOC` 把该条的 `evidence_files` 写入事件 `context`；
- 后续命中：`mergeOccurrence` 只累加 `occurrence_count`、首/末时间、
  `occurrences` 明细与量化统计，**不合并后续命中的 `evidence_files`**；
- 现有单文件下载接口 `GET /events/detail/:eventID/evidence/:idx` 只能取到
  聚合事件内**首次命中**携带的 PCAP，后续命中的 PCAP 无索引、不可下载。

需求：聚合事件提供“下载全部 PCAP ZIP”，一次取回该聚合事件首末命中区间
（即全部聚合命中）对应的所有 PCAP。

## 2. 目标与范围

目标：

1. 合并命中时累积 `evidence_files`（按 path_ref/sha256 去重），并记录每个
   附件所属的命中序号、命中时间与来源节点；
2. 新增 ZIP 打包下载接口，管理端从节点代理拉取全部证据并**流式打包**返回；
3. 前端事件详情提供“下载全部 PCAP(ZIP)”入口，单文件下载保持不变；
4. 兼容存量事件与 schema 1.5 事件（无 `evidence_files` 时按钮隐藏/404）。

本期范围：

- 仅管理端 traffic 事件侧，不新增节点侧接口；
- 报告/incident 附件透传不在本期；
- 存量聚合事件的后续命中证据无法补齐（原因见 §6）。

## 3. 数据模型：evidence_files 累积

继续使用 `context.evidence_files` 扁平数组，元素在节点原始字段基础上追加
管理端元数据（节点推送时不存在的字段，管理端写入）：

```json
{
  "id": "data/evidence/node-arm-offline-001/2026-08-06/evt-xxx.pcap",
  "name": "evt-xxx.pcap",
  "type": "pcap",
  "path_ref": "/api/v1/evidence/node-arm-offline-001/2026-08-06/evt-xxx.pcap",
  "sha256": "",
  "size": 12345,
  "description": "触发包 PCAP 证据",
  "device_id": "node-arm-offline-001",
  "occ_idx": 2,
  "occ_time": "2026-08-06T10:15:30Z"
}
```

| 追加字段 | 类型 | 说明 |
| --- | --- | --- |
| `device_id` | string | 该附件来源节点；多节点聚合时以文件级为准，缺失时回退事件级 `device_id` |
| `occ_idx` | int | 对应 `occurrences[]` 下标（首条命中=0） |
| `occ_time` | string | 命中时间（`occurrence_time`/`time`），用于 ZIP 条目命名 |

合并规则：

1. 首次创建（`LyEventToDeepSOC`）：对该条 `evidence_files` 逐项注入
   `device_id=ly.device_id`、`occ_idx=0`、`occ_time=occurrence_time`；
2. `mergeOccurrence`：先规范化本条 `evidence_files`（注入当前 `occ_idx` 与
   命中时间），再按去重键合并进 `ctx["evidence_files"]`：
   - 去重键优先 `sha256`（非空时），否则 `path_ref`；
   - 已存在 → 跳过（保留首次出现的 `occ_idx/occ_time`），不重复计数；
   - 不存在 → 追加到数组末尾；
3. 上限 `maxEvidenceFiles = 200`（与 `maxOccurrences` 一致）：超出后丢弃新
   文件并在 context 写入 `evidence_truncated=true`，避免 context 无限膨胀；
4. 旧元素（无 `occ_idx`）原样保留、视为 `occ_idx=-1`，不做破坏性迁移；
5. `occurrences[]` 结构不变（不把证据塞进每次命中明细），避免前端与报告大改。

LLM prompt 与现有单文件接口复用同一数组：累积后 prompt 中的“证据附件摘要”
会自动覆盖全部附件；`evidence/:idx` 的 `idx` 指向累积后的数组下标，对
首条证据的语义与现在一致。

## 4. 后端接口设计

新增（鉴权与现有事件详情接口一致）：

```
GET /api/traffic/events/detail/:eventID/evidence/archive
```

返回 `application/zip`，`Content-Disposition: attachment; filename="<eventID>_evidence.zip"`。

处理流程：

1. 读取事件，解析 `context.evidence_files`；事件不存在/数组为空 → 404
   （与单文件接口语义一致）；
2. 文件级节点解析：`deviceID = firstNonEmpty(file.device_id, ctx.device_id)`，
   `base = cfg.EvidenceNodes[deviceID]`；未配置 → 该文件记为失败，继续；
3. 逐文件校验 `path_ref`（沿用 `validEvidencePath`：`/api/v1/evidence/`
   前缀、无 `..`、无 `\`、无 `://`）；
4. 逐文件代理拉取（复用单文件代理的节点请求逻辑：GET、Content-Type 校验
   pcap/octet-stream、单文件超时 10s、单文件 ≤20MB），**流式写入 zip**：
   - ZIP 条目名：`{occ_idx 三位零填充}_{命中时间紧凑格式}_{原文件名}`，
     如 `002_20260806T101530Z_evt-xxx.pcap`；
   - 时间缺失/为旧元素时用 `999_` 前缀，保证条目名唯一（重复时自动加序号）；
   - 不整体缓冲到内存，逐文件 `io.Copy` 进 `archive/zip.Writer`；
5. 失败策略（推荐）：单文件失败不中断，写入 `_下载失败清单.txt`（UTF-8，
   列出文件名/节点/失败原因），ZIP 正常返回；全部失败 → 502 返回首个错误；
   响应头 `X-Evidence-Failed: n` 标记失败数量；
6. 限制（防内存/时间爆炸）：
   - 文件数 ≤ 200（超出时按 §3 已截断，接口不再重复截断）；
   - 累计大小 ≤ 500MB，超限终止并返回 413/502（带已写入部分已丢弃）；
   - 整体请求超时 120s（v1 串行拉取，节点单文件超时 10s）。

实现落点：

- `InternalService.EvidenceArchive(ctx, eventID, w io.Writer) (EvidenceZipResult, error)`
  负责拉取与写 zip（不依赖 gin，便于测试）；
- `handler.go` 新增 `EventEvidenceArchive`，设置响应头后调用 service；
- `traffic.go` 路由注册新增
  `{Name: "证据PCAP全量打包", Path: "detail/:eventID/evidence/archive", Method: "GET", ...}`；
- `services.go mergeOccurrence` 增加证据合并；`event_mapping.go` 首次注入元数据。

## 5. 前端设计

1. `deepflow.ts` 新增
   `deepflowEventArchiveUrl(eventId) => /api/traffic/events/detail/${eventId}/evidence/archive`；
2. `LyEventTable.vue` 证据附件卡片标题栏增加“下载全部 PCAP(ZIP)”按钮：
   - `evidence_files` 非空即展示（单个文件也可打包，保持行为统一）；
   - 使用 `<a :href target="_blank" rel="noopener">` 直接触发下载；
   - 样式与现有“证据附件”卡片保持一致；
3. 部分失败提示：v1 不读取响应头做前端弹窗（文件流下载难取头），
   依赖包内 `_下载失败清单.txt`；如后续需要再改为 fetch blob 方案。

## 6. 存量数据与回填限制

- 本改动自部署后生效：新推送/新合并的聚合事件会累积全部命中证据；
- 已入库聚合事件的 context 只有首次命中的 `evidence_files`（或无），
  `pushed_events` 只存 ID/幂等键、不存原始 payload，节点也没有按时间或规则
  列举证据的接口，**无法从现有数据恢复后续命中的 path_ref**；
- 如需补齐存量，需节点新增列举接口（如
  `GET /api/v1/evidence/list?device_id=&start=&end=&rule_id=`）后由管理端
  回填；此为节点侧二期，本期不做。

## 7. 已确认决策

1. 接口路径：`GET /api/traffic/events/detail/:eventID/evidence/archive`；
2. 单文件失败策略：部分失败打包+清单（`_下载失败清单.txt`），全部失败 502；
3. 拉取方式：**并发拉取**（并发数 4）到临时目录，再流式写 zip；临时目录
   位于系统临时区，请求结束/失败均 `defer os.RemoveAll` 清理，不留缓存；
4. 存量事件：接受“仅部署后的聚合事件可全量下载”，节点侧 list 接口回填为二期；
5. 限制：文件数 ≤200（合并时截断并标记 `evidence_truncated`）、总量 ≤500MB、
   整体超时 120s。

## 8. 验收清单

1. 同一聚合键推送 3 条命中（各带不同 pcap）→ 详情附件 3 个，ZIP 含 3 个
   pcap，条目名为“序号_时间_文件名”；
2. 同一 `path_ref` 重复推送 → 附件不重复，ZIP 只含 1 个；
3. 单文件 404/超时 → ZIP 仍生成且含 `_下载失败清单.txt`；全部失败 → 502；
4. 未配置 `evidence_nodes[device_id]` → 对应文件进失败清单；
5. 存量无证据事件 → 前端不显示 ZIP 按钮，接口 404；
6. 单文件下载接口 `evidence/:idx` 行为不变；
7. `evidence_truncated=true` 时前端有提示（附件数已达上限）；
8. `go test ./traffic/...` 通过，新增单测覆盖：合并去重、ZIP 条目命名、
   单文件失败清单、上限截断。
