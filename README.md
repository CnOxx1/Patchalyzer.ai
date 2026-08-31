# Patchalyzer — Windows 驱动补丁分析 Web 系统

将当前离线分析流程做成 Web，并用 **LangGraph 多 Agent** 协同：工具节点负责 PE/PDB/Diff/反汇编，专家 Agent 负责解读与写报告。LLM 可配置（OpenAI 兼容）。

## LangGraph 协同

```
PEExtractor → SymbolDiffer → DisasmWorker     （确定性工具，与 analysis/ 脚本同方法）
     ↓              ↓              ↓
 PEAnalyst    SymbolAnalyst   DisasmAnalyst → ControlPathAnalyst
                                   ↓
                            RootCauseAnalyst → ReportWriter
```

| Agent | 类型 | 对应现有方法 |
|---|---|---|
| PEExtractor | tool | `extract_pe.py` |
| SymbolDiffer | tool | 下 PDB + `compare_symbols.py`（`.pdata` 尺寸） |
| DisasmWorker | tool | 变化函数 + Notify 对照（`dump_funcs.py`） |
| PEAnalyst | LLM | 同分支/跨版本风险 |
| SymbolAnalyst | LLM | 热点函数、Feature 符号 |
| DisasmAnalyst | LLM | 锁 / `TdiCopyMdlToBuffer` / 池释放 |
| ControlPathAnalyst | LLM | 排除 `AfdNotify*`（68820 方法论） |
| RootCauseAnalyst | LLM | 综合根因 |
| ReportWriter | LLM | Markdown 技术报告 |

不勾选 LLM 时只跑三个 tool 节点，仍可得到符号 diff 与反汇编。

## 功能

| 步骤 | 说明 |
|---|---|
| PE 提取 | 节区、导入表、PDB 调试目录 |
| PDB 下载 | Microsoft Symbol Server |
| 符号 Diff | 公开符号增删、`.pdata` 函数尺寸 |
| 反汇编 | Top 变化函数 + Notify 对照 |
| 多 Agent 报告 | LangGraph + 可配置 LLM |

## 快速开始

```bat
cd webapp
pip install -r requirements.txt
python run.py
```

浏览器打开：**http://127.0.0.1:8765**

前端为 `frontend/` 下的静态页面。

## LLM 配置

在 **LLM 配置** 页填写：

| 提供商 | Base URL | Model 示例 |
|---|---|---|
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` |
| Ollama | `http://127.0.0.1:11434/v1` | `llama3.2` |

API Key 保存在本地 SQLite（`webapp/data/patchalyzer.db`），不会提交到 git。

## 使用流程

1. **新建分析** — 上传漏洞版、修复版 `.sys`，填写 CVE/任务名  
2. 可选上传更早构建做三版本时间线（如 8875 vs 8972 vs 9168）  
3. 等待后台：PE → PDB → `.pdata` 尺寸 → 时间线 → 字节 diff → 全文反汇编 + Notify 对照  
4. 任务详情查看时间线 / 字节 diff / 反汇编 / Agent 报告，可下载 `report.md`  


## 目录结构

```
webapp/
  run.py                 # 启动入口
  requirements.txt
  backend/
    main.py              # FastAPI 路由
    config.py
    database.py
    agents/              # LangGraph 多 Agent
      graph.py           # StateGraph 编排
      nodes.py           # tool + 专家节点
    services/
      analyzer.py        # PE/PDB/diff/disasm 工具
      llm_service.py     # 连接测试 / 兼容入口
  frontend/              # 静态前端
  data/                  # 运行时数据（上传、任务、DB）
```

分析核心复用仓库根目录 `analysis/`（PDB 解析）与 `TOOLs/`（pefile/capstone）。

## API 概览

| Method | Path | 说明 |
|---|---|---|
| GET | `/api/health` | 健康检查 |
| GET/PUT | `/api/config/llm` | LLM 配置 |
| POST | `/api/config/llm/test` | 测试 LLM 连接 |
| GET | `/api/jobs` | 任务列表 |
| POST | `/api/jobs` | 创建分析（multipart 上传） |
| GET | `/api/jobs/{id}` | 任务详情 + 结果 |
| POST | `/api/jobs/{id}/report` | 重新生成 LLM 报告 |

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PATCHALYZER_HOST` | `127.0.0.1` | 监听地址 |
| `PATCHALYZER_PORT` | `8765` | 端口 |
| `PATCHALYZER_MAX_UPLOAD_MB` | `200` | 单文件上传上限 |

## 示例

使用本仓库已有样本（项目根目录）：

- 漏洞版：`afd26100.8972.sys` 或 `analysis/afd_10.0.26100.8972.sys`
- 修复版：`afd2608.sys`

上传后即可复现 CVE-2026-68820 分析流程。

## 注意事项

- 需要 **网络** 访问 Microsoft Symbol Server 下载 PDB
- LLM 报告为 **推断性分析**，请结合反汇编人工复核
- 仅用于授权安全研究
