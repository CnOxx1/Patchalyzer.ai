# Patchalyzer.ai

Windows 内核补丁对照与单文件审计平台。对齐漏洞版 / 修复版二进制，用确定性工具取证，再用固定人设的 LLM 专家写出可核对的中文报告。

服务对象是补丁负责人、防御方与安全运营，**不是** exploit 开发。

仓库：<https://github.com/CnOxx1/Patchalyzer.ai>

---

## 它做什么

两条主流程：

| 入口 | 何时用 | 产出 |
|---|---|---|
| **补丁对照** `/analyze`、`/patch` | 有 CVE，或有漏洞版 + 修复版 | 19 节技术报告：根因、漏洞链、IOC、在野利用、绕过面、残留 |
| **内核审计** `/audit` | 只有一份 `.sys` / `.dll` / `.exe`，没有补丁对 | 5 节短报告：用户入口、处理函数打分、缺陷类嫌疑、隔离 VM 观察清单 |

共同点：

- 证据来自 PE / PDB / `.pdata` 尺寸 / 反汇编 / CFG / Feature xref，禁止编造 RVA 与函数名。
- 结论旁区分【已证实】与【推断】。
- 不生成 exploit、PoC、payload，也不给出可复制的 IOCTL 触发序列。审计结果是 **嫌疑 + 观察条件**。

---

## 快速开始

需要 **Python 3.10+**、**Node.js 18+**（构建前端）、能访问 Microsoft 符号服务器。PDB 解析还依赖仓库上级目录的 `analysis/parse_pdb.py`（见 [依赖说明](#pdb-解析依赖)）。

```bat
git clone https://github.com/CnOxx1/Patchalyzer.ai.git
cd Patchalyzer.ai

pip install -r requirements.txt

cd ui
npm install
npm run build
cd ..

python run.py
```

浏览器打开 **http://127.0.0.1:8765**。

首次启动会创建管理员账号（用户名默认 `admin`，密码由环境变量 `PATCHALYZER_ADMIN_PASSWORD` 决定，未设置则用源码里的默认值）。登录后立刻改密。

开发前端可另开终端：

```bat
cd ui
npm run dev
```

Vite 在 `http://127.0.0.1:5173`，`/api` 会代理到 `8765`。生产由 FastAPI 直接托管 `ui/dist`。

---

## 产品界面

公开站：

| 路径 | 说明 |
|---|---|
| `/` | 落地页 |
| `/blog` | 公开研究报告 |
| `/login` | 登录 |

登录后工作台：

| 路径 | 说明 |
|---|---|
| `/app` | 工作台：待处理、KEV、绕过面、当前运行 |
| `/analyze` | 上传样本或填 CVE，启动补丁对照 |
| `/audit` | 上传单个内核模块，启动内核审计 |
| `/patch` | Patch Tuesday 公告、按 CVE 排队分析、可选自动监控 |
| `/jobs`、`/jobs/:id` | 任务列表与详情 |
| `/settings` | LLM（OpenAI 兼容）、专家提示词、GEPA |
| `/publish` | 把任务报告发成博客 |
| `/users` | 账号管理（管理员） |
| `/account` | 当前用户 |

补丁对照任务详情按四组页签组织：结论（决策 / 漏洞链）、检测（IOC / 在野 / 绕过面 / 残留）、完整报告、证据（流水线 / 对照 / 时间线 / 字节 / 符号 / 反汇编 / CFG / Feature / 验证包 / HuntLab）。

---

## 架构

分析跑在独立子进程里（`backend/worker_cli.py`），API 进程只负责 HTTP、鉴权、SSE 进度和排队。并发上限 `PATCHALYZER_ANALYSIS_CONCURRENCY`（默认 2）。`uvicorn` 使用 `reload=False`，改后端需重启 `python run.py`。

### 系统分层

```mermaid
flowchart TB
  subgraph client["浏览器"]
    SPA["Vue 3 SPA  ui/src → ui/dist"]
  end

  subgraph http["FastAPI  python run.py"]
    MAIN["backend/main.py"]
    AUTH["auth.py  会话 cookie"]
    SSE["GET /api/jobs/events"]
  end

  subgraph child["分析子进程  worker_cli"]
    FULL["kind=full  补丁对照"]
    AUD["kind=audit  内核审计"]
    TAIL["kind=hotspot / llm  重跑"]
  end

  subgraph graphs["编排"]
    LG["LangGraph  agents/graph.py"]
    KA["kernel_audit.py"]
    BOX["agent_tools  白名单工具箱"]
  end

  subgraph disk["落盘"]
    DB["SQLite  data/patchalyzer.db"]
    JOB["data/jobs/id/"]
    CACHE["pdb_cache / cache/msrc"]
  end

  SPA -->|"REST + cookie"| MAIN
  SPA --> SSE
  MAIN --> AUTH
  MAIN -->|"spawn"| FULL
  MAIN -->|"spawn"| AUD
  MAIN -->|"spawn"| TAIL
  MAIN --> DB
  SSE -->|"读 progress.json"| JOB
  FULL --> LG
  TAIL --> LG
  AUD --> KA
  LG --> BOX
  KA --> BOX
  FULL --> JOB
  AUD --> JOB
  FULL --> DB
  AUD --> DB
  LG --> CACHE
  KA --> CACHE
```

### 模块职责

| 层 | 路径 | 职责 |
|---|---|---|
| HTTP / 鉴权 | `backend/main.py`、`auth.py` | 任务、登录、博客、补丁日、HuntLab / 研究流程 |
| 子进程调度 | `worker_proc.py`、`analysis_worker.py` | 拉起 / 监护 / 重挂活着的分析进程 |
| 图编排 | `backend/agents/graph.py` | 工具边、专家扇出、`finalize_soc` |
| 节点 | `backend/agents/nodes.py` | 每个 tool / 专家的输入输出 |
| 状态 | `backend/agents/state.py` | `PatchState` |
| LLM | `backend/agents/llm.py` | ChatOpenAI（OpenAI 兼容）；提示词来自设置或默认 |
| 确定性分析 | `backend/services/analyzer.py` | PE / PDB / `.pdata` / 反汇编 / CFG / Feature |
| 表面图 | `backend/services/surface.py` | IOCTL / FastIo / Immediate / MajorFunction |
| 缺陷类扫描 | `backend/services/lpe_patterns.py` | 缺 Probe、缺锁、生命周期、检查-使用窗口 |
| 内核审计 | `backend/services/kernel_audit.py` | 单文件流水线、入口 agent、断点续跑 |
| 工具箱 | `backend/services/agent_tools.py` | 白名单工具 + 有界 tool loop（流水线 / HuntLab / 审计共用） |
| 补丁解析 | `backend/services/patch_resolver.py` | CVE → MSRC + Winbindex 成对样本 |
| 补丁监控 | `backend/services/patch_watch.py` | 定时看新公告，可选自动排队 |
| IOC / 情报 / 评审 | `ioc.py`、`threat_intel.py`、`patch_review.py` | 覆盖报告 §16–§19 |
| HuntLab | `hunt_lab.py` | 图外深度狩猎（绕过面 + 变体） |
| 研究流程 | `research_lab.py` | 对照任务完成后的独立入口狩猎 |
| GEPA | `gepa_optimize.py` | 离线回放已完成任务优化提示词，不进在线流水线 |
| 前端 | `ui/src` | 工作台、对照、审计、补丁日、报告渲染（Markdown / Mermaid） |

### 运行时交互

```mermaid
sequenceDiagram
  participant U as 浏览器
  participant A as FastAPI
  participant Q as 分析队列
  participant W as 子进程
  participant D as SQLite / jobs 目录

  U->>A: POST /api/jobs 或 /api/jobs/audit
  A->>D: create_job status=pending
  A->>Q: spawn_worker
  A-->>U: job_id
  Q->>W: worker_cli kind=full 或 audit
  W->>D: status=running 写 progress.json
  loop 直到结束
    U->>A: SSE /api/jobs/events 或 GET /jobs/id
    A->>D: 读进度
    A-->>U: percent / message
  end
  W->>D: artifacts + completed 或 failed
  U->>A: 下载 report.md / audit.json
```

三张 LangGraph（均在 `agents/graph.py`）：

| 函数 | Worker kind | 用途 |
|---|---|---|
| `build_graph()` | `full` | 完整对照：工具 + 编制 + 13 专家 |
| `build_tail_graph()` | `hotspot` | 加选热点后从 `pick_hotspots` 重跑尾部 |
| `build_llm_graph()` | `llm` | 只重跑编制 + 专家，不再下 PDB / 反汇编 |

每个节点包在 `guarded()` 里：检查取消、报进度、按 `checkpoints/{node}.json` 跳过、写断点。

---

## 逻辑流程

一句话：**入口（上传 / CVE / 补丁日）→ 成对或单文件落盘 → 子进程取证 →（对照则专家图 / 审计则入口 agent）→ 报告与 JSON 入库 → 前端页签。** 图外的 HuntLab、研究流程、GEPA 不并进 19 节正文。

### 任务生命周期

```mermaid
flowchart TD
  CREATE["POST 创建任务  pending"] --> KIND{kind}

  KIND -->|"patch_diff"| PAIR{样本是否成对}
  PAIR -->|"无漏洞样本"| CVE1["CVE → MSRC KB + Winbindex 成对下载"]
  PAIR -->|"有漏洞无修复"| CVE2["按 CVE 拉同分支更高构建"]
  PAIR -->|"已上传成对"| RUN
  CVE1 --> RUN["子进程 running"]
  CVE2 --> RUN

  KIND -->|"kernel_audit"| SAMPLE["已有 sample_*.sys"]
  SAMPLE --> RUN

  RUN --> WORK{流水线}
  WORK -->|"对照"| GRAPH["LangGraph 工具 + 专家"]
  WORK -->|"审计"| AUDIT["PE → 表面图 → 入口 agent"]
  GRAPH --> FIN["finalize_soc 注入 IOC / 情报 / 绕过 / 残留"]
  AUDIT --> PACK["kernel_audit.json + audit.md"]
  FIN --> OUT{收尾}
  PACK --> OUT

  OUT -->|"成功"| OK["completed"]
  OUT -->|"取消"| CAN["cancelled"]
  OUT -->|"异常"| FAIL["failed"]
  OK -->|"报告空 / llm_error / 入口未跟完"| RESUME["POST /jobs/id/resume"]
  FAIL --> RESUME
  CAN --> RESUME
  RESUME --> RUN
```

不能从 Update Catalog 解 MSU/CAB；文件名从 MSRC 标题推断（可手填）；Winbindex 可能落后于 Patch Tuesday。

### 补丁对照主图

对照 `backend/agents/graph.py` 的边。工具阶段可并行；专家阶段两处扇出汇合。

```mermaid
flowchart TD
  START([START]) --> pe_extract
  pe_extract --> pdb_symbols
  pdb_symbols --> feature
  pdb_symbols --> byte_diff
  feature --> pick_hotspots
  byte_diff --> pick_hotspots
  pick_hotspots --> timeline
  pick_hotspots --> disasm
  disasm --> cfg
  timeline --> join_tools
  cfg --> join_tools
  cfg --> verify_pack
  verify_pack --> END_V([verify 旁路结束])
  join_tools --> route_agents

  route_agents --> pe_analyst
  route_agents --> symbol_analyst
  route_agents --> disasm_analyst
  route_agents --> feature_analyst

  pe_analyst --> control_analyst
  symbol_analyst --> control_analyst
  disasm_analyst --> control_analyst
  feature_analyst --> control_analyst

  control_analyst --> root_cause
  root_cause --> detection_analyst
  root_cause --> threat_intel
  root_cause --> hunt_prep

  hunt_prep --> bypass_analyst
  hunt_prep --> residual_analyst
  hunt_prep --> alias_site_analyst
  hunt_prep --> feature_off_analyst

  detection_analyst --> report_writer
  threat_intel --> report_writer
  bypass_analyst --> report_writer
  residual_analyst --> report_writer
  alias_site_analyst --> report_writer
  feature_off_analyst --> report_writer
  report_writer --> ENDN([END])
```

设计意图：

- Feature 与字节差在热点选择之前并行，xref 能进热点名单。
- 时间线与反汇编在热点确定后并行；CFG 依赖反汇编。
- `verify_pack` 从 CFG 旁路到 END，不挡专家；`join_tools` 等时间线 + CFG 齐了再编制。
- 四专家并行 → 对照路径汇合 → 根因。
- 根因后：SOC（检测 / 情报）与 HuntPrep 并行；HuntPrep 后再并行 Bypass / Residual / Alias / FeatureOff。
- ReportWriter 吃齐六路再执笔。收尾 `finalize_soc` 注入 §16–§19 表格，并用调用差覆盖 §6 函数逻辑图。

未勾选 LLM 或未配 Key：工具照跑，专家节点写「跳过」，图不中断。某个专家失败：该节点记 `llm_error`，图仍前进。

### 内核审计主图

单文件、无 patched_pattern。确定性扫描之后，每个用户可达 API 一个跟链 agent。

```mermaid
flowchart TD
  UP["上传 .sys / .dll / .exe"] --> PE["extract_pe"]
  PE --> PDB["fetch_pdb"]
  PDB --> SUR["build_surface_map"]
  SUR --> DIS["反汇编 high / medium handler"]
  DIS --> CAL["跟本模块 callee"]
  CAL --> SCAN["classify_audit 四类模式"]
  SCAN --> APIS["collect_hunt_apis 最多 32"]
  APIS --> LOOP{"还有未完成入口?"}
  LOOP -->|"resume: 跳过 path_agents 里已完成的"| LOOP
  LOOP -->|"是"| AGENT["run_tool_loop PATH_SYSTEM"]
  AGENT --> PUB["_publish_partial 写 kernel_audit.json"]
  PUB --> Q402{"LLM 额度错误?"}
  Q402 -->|"是"| STOP["停后续入口 保留 checkpoint"]
  Q402 -->|"否"| LOOP
  STOP --> WRITE["执笔 5 节 或离线模板"]
  LOOP -->|"否"| WRITE
  WRITE --> OUT2["audit.md + 任务 completed"]
```

### 单入口 agent 跟链

每个 agent 只跟一条入口。`unresolved` 非空不能 `done`。已加固 / wrapper 用短预算（5 轮 / 12 次工具），其余满预算（14 / 32）。预算耗尽则剩余跳写入 `blocked`（`budget_exhausted`）。

```mermaid
flowchart TD
  H["入口 handler"] --> D["disasm"]
  D --> CALL{"CALL / 导入目标"}
  CALL -->|"本模块符号"| D
  CALL -->|"其它 .sys / .dll"| IMP["list_imports"]
  IMP --> LM["load_module 文件名"]
  LM --> D2["disasm name module=该文件"]
  D2 --> CALL
  CALL -->|"Probe / MDL / 锁挡住"| CL["findings: cleared"]
  CALL -->|"有汇编证据"| SU["findings: suspect"]
  CALL -->|"还能继续跟"| UN["写入 unresolved 禁止 done"]
  CALL -->|"load 失败或无符号"| BK["blocked 附原因 可以 done"]
  UN --> D
  CL --> JSON["输出 done JSON"]
  SU --> JSON
  BK --> JSON
```

共享 trampoline（`DispatchDeviceControl` / `ImmediateCallDispatch` 等）折叠到表目标，避免几十个重复 dispatcher agent。

### 图外能力（不进 19 节）

```mermaid
flowchart LR
  DONE["对照任务 completed"] --> HL["HuntLab  绕过面 + 变体"]
  DONE --> RS["研究流程  入口表面图狩猎"]
  DONE --> GP["GEPA  离线优化提示词"]
  HL --> HMD["hunt_lab.md"]
  RS --> RMD["research.md"]
  GP --> SET["写回设置里的专家 prompt"]
```

| 入口 | 说明 |
|---|---|
| `POST /jobs/{id}/hunt-lab` | 独立工具循环，两轨：补丁完整性 / 同类变体 |
| `POST /jobs/{id}/research` | 对照完成后的入口狩猎，禁止 IOCTL 触发步骤 |
| `POST /api/config/llm/gepa` | 用历史任务进化当前选中分析师的 prompt |

---

## 补丁对照流水线

### 怎么发起

1. **上传** `/analyze`：CVE 必填；漏洞样本可选。不传样本则按 CVE 从 MSRC KB + Winbindex 下载同分支「漏洞版 → 修复版」（优先 amd64）。可另传修复版、更早构建（三版本尺寸时间线）。
2. **补丁日** `/patch`：选某期公告里的 CVE，不上传文件。
3. **监控**：打开自动分析后，新补丁日最多再排队若干内核向 CVE（首次打开不会把当月全部倒进去）。

主图见 [逻辑流程 · 补丁对照主图](#补丁对照主图)。证据优先级：**`.pdata` 函数尺寸 > 反汇编 / 调用差 > Feature xref > 字节差**（字节差含 RIP 重定位噪声）。

### 工具阶段（确定性）

| 节点 | 做什么 |
|---|---|
| `pe_extract` | 节区、导入、PDB 调试目录、FileVersion |
| `pdb_symbols` | Microsoft 符号服务器下 PDB，公开符号增删、`.pdata` 尺寸 |
| `feature` | Feature_* 开关与 xref |
| `byte_diff` | 代码节字节差 |
| `pick_hotspots` | 尺寸变化优先，辅以 Feature / 字节差 |
| `timeline` | 两版或三版尺寸时间线 |
| `disasm` | 热点 + 对照函数反汇编 |
| `cfg` | 控制流差，写出 `cfg_diff.html` |
| `verify_pack` | 隔离 VM 核对材料（服务器不跑 PoC） |
| `route_agents` | 按证据裁剪本轮专家（自动编制）或按勾选全跑（手动） |

未勾选 LLM 或未配 API Key：工具照跑，专家节点写「跳过」，图不中断。

### 13 个专家

人设固定，自动编制只决定「本轮跑哪些」，不发明新人格。

| Agent | 职责 |
|---|---|
| PEAnalyst | 版本 / 架构归因，跨大版本警告 |
| SymbolAnalyst | 热点函数、Feature 符号 |
| DisasmAnalyst | 锁 / 释放 / Probe / 拷贝 |
| FeatureAnalyst | Feature 启用位与 xref |
| ControlPathAnalyst | 排除未改对照路径 |
| RootCauseAnalyst | 综合根因 |
| DetectionAnalyst | IOC / 检测要点 |
| ThreatIntelAnalyst | 在野利用（检索 + KEV / NVD / EPSS） |
| BypassAnalyst | 补丁完整性：门控关闭、未改调用点、检查-使用窗口 |
| FeatureOffAnalyst | Feature 关闭是否回到旧链 |
| ResidualVulnAnalyst | 未改兄弟函数上的同类缺陷 |
| AliasSiteAnalyst | 补丁只打在部分 CALL 点 |
| ReportWriter | 按 19 节模板执笔 |

HuntPrep 是确定性节点：补未改兄弟反汇编，并用调用克隆 / CFG 缺口扩候选，再扇出 Bypass / Residual / Alias / FeatureOff。

### 19 节报告

编号与标题不可改、不可合并：

1. 执行摘要  
2. 分析方法论  
3. CVE/MSRC 描述对照  
4. 漏洞根因  
5. 竞态/同步时序  
6. 漏洞链（总览表 + 函数逻辑图 + 原语 + 补丁切断点）  
7. 汇编证据  
8. 伪代码对比  
9. 状态机/标志位  
10. Feature 开关  
11. 用户态触发面  
12. 利用难度与影响  
13. 对照路径排除  
14. 修复有效性与残余风险  
15. 附录  
16. IOC / 检测方法  
17. 在野利用 / 威胁情报  
18. 补丁完整性 / 绕过面  
19. 残留漏洞 / 同类缺陷  

§16–§19 的表由系统用 IOC / 情报 / Bypass / Residual 包注入，执笔人只写要点。任务完成后可单独开 **HuntLab**（深度狩猎）或 **研究流程**，报告写入 `hunt_lab.md` / `research.md`，不并进 19 节正文。

失败或未写完的任务可 **从断点继续**（按节点 checkpoint）。也可「重跑热点尾部」或「只重跑报告」（不再下 PDB / 反汇编）。

---

## 内核审计流水线

面向「手头只有一份驱动」：没有 patched_pattern，不对照修复版。主图与跟链循环见 [逻辑流程 · 内核审计主图](#内核审计主图) 与 [单入口 agent 跟链](#单入口-agent-跟链)。

入口选择（最多 32 个 agent）：

- METHOD_NEITHER / Direct IOCTL 的独立处理函数
- Immediate 表已填槽
- FastIo 数据路径 callee
- high / medium 的 MajorFunction

共享 trampoline（如 `DispatchDeviceControl`、`ImmediateCallDispatch`）会折叠到表目标，避免几十个重复 dispatcher agent。已加固 / wrapper 入口用短预算（5 轮 / 12 次工具），其余用满预算（14 轮 / 32 次）。

每个 agent 必须把 `unresolved` 清空才能 `done`：本模块继续 `disasm`，跨模块 `list_imports` → `load_module` → `disasm(name, module=...)`。预算耗尽时剩余跳写入 `blocked`（`budget_exhausted`）。

额度不足（如 LLM 402）会 **停掉后续入口**，已完成的写入 `path_agents.json`。任务仍标完成，但带 `error`；页面可 **从断点继续**，只重跑未完成入口，并增量刷新 `kernel_audit.json`。

5 节报告：

1. 结论  
2. 用户入口（IOCTL / FastIo / MajorFunction）  
3. 处理函数打分  
4. 缺陷类证据  
5. 隔离 VM 观察清单  

关闭 LLM 时只跑确定性扫描与打分，仍可下载 JSON。

---

## 白名单分析工具

流水线专家、HuntLab、内核审计共用同一工具箱，无 shell、无任意代码执行。未知工具名会被拒绝。

`pe_info` · `list_symbols` · `function_meta` · `disasm` · `cfg_blocks` · `call_neighbors` · `xrefs` · `patched_pattern` · `feature_info` · `read_evidence` · `compare_calls` · `ioctl_table` · `handler_score` · `list_imports` · `load_module`

`disasm` 返回兴趣指令与函数头尾，不是全文。跨模块必须先 `load_module`。

---

## LLM 配置

在 **设置** 页填写 OpenAI 兼容接口。API Key 存在本地 SQLite（`data/patchalyzer.db`），不进 git。

| 提供商 | Base URL | Model 示例 |
|---|---|---|
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` |
| Ollama | `http://127.0.0.1:11434/v1` | `llama3.2` |

可按专家改 system prompt。GEPA 在设置页对已完成任务离线回放，优化提示词，不进入分析图。

---

## 目录结构

```
（本仓库根 = 原工作区 webapp/）
  run.py                      uvicorn 入口
  requirements.txt
  README.md
  backend/
    main.py                   FastAPI
    config.py                 路径、19 节模板、专家 prompt、环境变量
    database.py               SQLite：jobs / llm_config / users / blog
    auth.py
    agents/                   LangGraph
    services/                 分析、审计、补丁日、情报
    tests/                    unittest
  ui/                         Vue 3 前端（npm run build → ui/dist）
  docs/                       流程与架构长文（部分仍写旧 frontend/ 路径，以本 README 为准）
  data/                       运行时（gitignore）
    patchalyzer.db
    pdb_cache/
    cache/msrc/
    jobs/{job_id}/
```

单次补丁对照任务目录常见产物：`old_vulnerable.sys` / `new_patched.sys`、`symbol_diff.json`、`feature_trace.json`、`byte_diff.json`、`disasm/`、`cfg_diff.html`、`hotspots.json`、`hunt_brief.json`、`checkpoints/`、`report.md`、`ioc.json`、`verify/`。

单次内核审计：`sample_*.sys`、`kernel_audit.json`、`path_agents.json`、`audit.md`。

---

## PDB 解析依赖

`backend/config.py` 从 **本仓库的上一级目录** 读取：

- `../analysis/parse_pdb.py` — PDB 7 公开符号与过程尺寸（必需）
- `../TOOLs/` — 历史路径；pefile / capstone 已由 `requirements.txt` 安装

从 GitHub 单独克隆本仓库时，请把 `parse_pdb.py` 放到与克隆目录同级的 `analysis/` 下：

```
somewhere/
  analysis/parse_pdb.py
  Patchalyzer.ai/          ← 本仓库
    run.py
    backend/
```

没有该文件则无法解析 PDB，符号差与函数尺寸会失败。

---

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PATCHALYZER_HOST` | `127.0.0.1` | 监听地址 |
| `PATCHALYZER_PORT` | `8765` | 端口 |
| `PATCHALYZER_MAX_UPLOAD_MB` | `200` | 单文件上传上限 |
| `PATCHALYZER_ANALYSIS_CONCURRENCY` | `2` | 同时跑的分析子进程数（1–8） |
| `PATCHALYZER_ADMIN_USER` | `admin` | 空库时创建的管理员用户名 |
| `PATCHALYZER_ADMIN_PASSWORD` | （源码默认） | 空库时管理员密码；部署务必覆盖 |
| `PATCHALYZER_SESSION_DAYS` | `7` | 登录 cookie 有效期 |

---

## API 概览

除公开博客与登录外，接口需要会话 cookie。

| Method | Path | 说明 |
|---|---|---|
| GET | `/api/health` | 健康检查 |
| POST | `/api/auth/login` | 登录 |
| POST | `/api/auth/logout` | 退出 |
| GET | `/api/auth/me` | 当前用户 |
| GET/PUT | `/api/config/llm` | LLM 配置 |
| POST | `/api/config/llm/test` | 测连通 |
| POST | `/api/jobs` | 创建补丁对照（multipart） |
| POST | `/api/jobs/audit` | 创建内核审计（multipart，字段 `sample`） |
| POST | `/api/jobs/from-cve` | 从补丁日 CVE 排队 |
| GET | `/api/jobs` | 任务列表 |
| GET | `/api/jobs/events` | SSE 进度 |
| GET | `/api/jobs/{id}` | 详情 |
| POST | `/api/jobs/{id}/cancel` | 取消 |
| POST | `/api/jobs/{id}/resume` | 从断点继续（对照 checkpoint / 审计 path_agents） |
| POST | `/api/jobs/{id}/report` | 只重跑 LLM 报告 |
| POST | `/api/jobs/{id}/hotspots` | 加选热点并重跑尾部 |
| GET | `/api/jobs/{id}/report.md` | 下载 19 节报告 |
| GET | `/api/jobs/{id}/audit.json` | 审计 JSON |
| GET | `/api/jobs/{id}/audit.md` | 审计 Markdown |
| GET | `/api/jobs/{id}/ioc.json` 等 | IOC / 情报 / bypass / residual / CFG / verify.zip |
| POST | `/api/jobs/{id}/hunt-lab` | 启动 HuntLab |
| POST | `/api/jobs/{id}/research` | 启动研究流程 |
| GET/POST | `/api/patch-tuesday` | 补丁日目录 |
| GET/PUT | `/api/config/watch` | 监控开关 |

---

## 测试

在仓库根目录：

```bat
python -m unittest discover -s backend/tests -v
```

覆盖内核审计入口拆分、预算耗尽、额度错误停跑、模块解析与 LPE 模式扫描。

---

## 硬约束

- 不在 UI、提示词、Bypass / HuntLab / 审计 agent 中给出 exploit、PoC 或逐步绕过配方。
- RVA、指令、Feature ID、哈希必须来自工具证据。
- 专家目录固定 13 人；GEPA 只离线跑。
- 审计 findings 的 `status` 为 suspect / similar / cleared，需人工在隔离环境核对。

仅用于授权安全研究。

---

## 更多文档

`docs/` 里有更长的流程说明。其中部分章节仍按早期静态 `frontend/` 与专家人数撰写，**以本 README 与当前源码为准**。
