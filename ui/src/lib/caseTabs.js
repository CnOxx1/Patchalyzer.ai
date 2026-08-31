export const PANEL_GROUP = {
  summary: "conclude",
  chain: "conclude",
  fullreport: "report",
  ioc: "detect",
  threat: "detect",
  bypass: "detect",
  residual: "detect",
  community: "evidence",
  control: "evidence",
  timeline: "evidence",
  bytediff: "evidence",
  symbols: "evidence",
  disasm: "evidence",
  cfg: "evidence",
  feature: "evidence",
  verify: "evidence",
  huntlab: "evidence",
};

export const GROUP_DEFAULT = {
  conclude: "summary",
  detect: "ioc",
  report: "fullreport",
  evidence: "community",
};

export const PRIMARY_GROUPS = [
  { id: "conclude", label: "结论" },
  { id: "detect", label: "检测" },
  { id: "report", label: "报告" },
  { id: "evidence", label: "证据" },
];

export const SUB_TABS = {
  conclude: [
    { id: "summary", label: "决策" },
    { id: "chain", label: "漏洞链" },
  ],
  detect: [
    { id: "ioc", label: "IOC / 检测" },
    { id: "threat", label: "在野利用" },
    { id: "bypass", label: "绕过面" },
    { id: "residual", label: "残留漏洞" },
  ],
  evidence: [
    { id: "community", label: "流水线" },
    { id: "control", label: "对照" },
    { id: "timeline", label: "时间线" },
    { id: "bytediff", label: "字节" },
    { id: "symbols", label: "符号" },
    { id: "disasm", label: "反汇编" },
    { id: "cfg", label: "CFG" },
    { id: "feature", label: "Feature" },
    { id: "verify", label: "验证包" },
    { id: "huntlab", label: "深度狩猎" },
  ],
};

export function panelGroup(name) {
  return PANEL_GROUP[name] || "conclude";
}
