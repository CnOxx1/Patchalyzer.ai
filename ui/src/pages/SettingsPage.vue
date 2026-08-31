<template>
  <div class="pa-page settings">
    <PageHeader title="设置" :sub="admin ? '配置模型与专家提示词。保存后对新任务和重新生成的报告生效。' : '配置模型。保存后对新任务生效。'">
      <button class="pa-btn" type="button" id="test-llm">测试连接</button>
      <button class="pa-btn primary" type="submit" form="settings-form">保存</button>
    </PageHeader>
    <div class="pa-stack">
      <div class="pa-card flush">
        <div class="settings-toolbar">
          <nav class="settings-tabs-inline">
            <button type="button" :class="{ on: tab === 'llm' }" @click="tab = 'llm'">模型</button>
            <button v-if="admin" type="button" :class="{ on: tab === 'prompts' }" @click="tab = 'prompts'">提示词</button>
          </nav>
          <p id="settings-msg" class="msg"></p>
        </div>
        <form id="settings-form" class="settings-body" @submit.prevent>
        <div id="s-llm" class="s-pane" :class="{ active: tab === 'llm' }">
          <p class="panel-lead">配置 OpenAI 兼容 API，用于生成分析报告。</p>
          <div class="form-grid">
            <label>Provider<input name="provider" placeholder="openai" /></label>
            <label>Model<input name="model" placeholder="gpt-4o-mini" /></label>
            <label class="full">Base URL<input name="base_url" placeholder="https://api.openai.com/v1" /></label>
            <label class="full">API Key<input name="api_key" type="password" placeholder="sk-…" autocomplete="off" /></label>
            <label>Temperature<input name="temperature" type="number" step="0.1" min="0" max="2" /></label>
            <label>Max Tokens<input name="max_tokens" type="number" min="256" max="128000" /></label>
          </div>
          <p id="key-preview" class="hint"></p>
          <div class="presets">
            <span>预设</span>
            <button type="button" class="preset" data-url="https://api.openai.com/v1" data-model="gpt-4o-mini">OpenAI</button>
            <button type="button" class="preset" data-url="https://api.deepseek.com/v1" data-model="deepseek-chat">DeepSeek</button>
            <button type="button" class="preset" data-url="http://127.0.0.1:11434/v1" data-model="llama3.2">Ollama</button>
          </div>
        </div>
        <div id="s-prompts" class="s-pane" :class="{ active: tab === 'prompts' }">
          <p class="panel-lead">全局约束作用于所有 Agent；各专家提示词只作用于对应节点。</p>
          <div class="form-grid">
            <label>报告语言
              <select name="language">
                <option value="zh">中文</option>
                <option value="en">English</option>
              </select>
            </label>
            <label class="full">额外关注（可选）
              <input name="extra_focus" placeholder="例如：重点分析 Feature 开关与竞态，忽略纯重定位噪声" />
            </label>
            <label class="full">全局约束
              <textarea name="system_prompt" rows="5"></textarea>
            </label>
            <label class="full">报告结构
              <textarea name="report_structure" rows="8"></textarea>
            </label>
            <label class="full">Agent 系统提示词
              <div class="prompt-toolbar">
                <select id="prompt-agent"></select>
                <button type="button" id="reset-agent-prompt" class="pa-btn">恢复该条默认</button>
                <button type="button" id="gepa-optimize" class="pa-btn">GEPA 优化当前</button>
              </div>
              <textarea id="agent-prompt-text" rows="8"></textarea>
            </label>
          </div>
          <p class="hint">修改后需重新生成报告才会生效。GEPA 用历史任务离线进化提示词，一次只优化当前选中的分析师。</p>
          <div class="pa-links" style="margin-top:1rem">
            <button type="button" id="reset-prompts" class="pa-btn">提示词恢复默认</button>
          </div>
        </div>
      </form>
      </div>
    </div>
  </div>
</template>
<script setup>
import { computed, onMounted, ref } from "vue";
import PageHeader from "../components/PageHeader.vue";
import { isAdmin } from "../lib/auth.js";
import { loadEngine } from "../lib/engine.js";

const tab = ref("llm");
const admin = computed(() => isAdmin());

onMounted(() => {
  loadEngine().then(m => m.loadSettings?.());
});
</script>
<style scoped>
.settings-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.35rem 1rem;
  padding: 0.15rem 1.15rem 0;
  min-height: 2.5rem;
  border-bottom: 1px solid var(--line);
  font-size: var(--text-md);
  color: var(--muted);
}
.settings-toolbar .msg { margin-left: auto; }
.settings-tabs-inline {
  display: flex;
  align-items: stretch;
}
.settings-tabs-inline button {
  background: none;
  border: 0;
  border-bottom: 2px solid transparent;
  padding: 0.55rem 0.7rem;
  color: var(--muted);
  cursor: pointer;
  font: inherit;
  font-size: var(--text-md);
}
.settings-tabs-inline button:hover { color: var(--ink); }
.settings-tabs-inline button.on {
  color: var(--ink);
  border-bottom-color: var(--accent);
  font-weight: 600;
}
.settings-body {
  overflow: visible;
}
.s-pane {
  display: none;
  padding: 1.15rem 1.4rem 1.6rem;
  max-width: 52rem;
}
.s-pane.active { display: block; }
.form-grid input, .form-grid select, .form-grid textarea {
  width: 100%;
  border: 1px solid var(--line-strong);
  background: #fff;
  padding: 0.55rem 0.7rem;
  border-radius: 8px;
  font: inherit;
}
.form-grid textarea { font-family: var(--mono); font-size: var(--text-sm); line-height: 1.5; }
.form-grid input:focus, .form-grid select:focus, .form-grid textarea:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(26, 115, 232, 0.12);
}
</style>
