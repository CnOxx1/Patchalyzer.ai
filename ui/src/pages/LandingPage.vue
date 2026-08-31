<template>
  <div class="home">
    <section class="hero">
      <div class="site-wrap hero-inner">
        <p class="hero-kicker">Introducing Patchalyzer</p>
        <h2>把每次 Patch Tuesday 变成可核对的结论</h2>
        <p class="lead">
          对齐 Windows 漏洞版与修复版二进制，定位函数尺寸变化与 Feature 开关，
          由多专家流水线写出根因、漏洞链、IOC 与补丁完整性判断。
          从公告到可运营结论，全程可回溯到样本与符号。
        </p>
        <div class="hero-cta">
          <router-link class="site-btn primary" :to="auth.user ? '/app' : '/login'">
            {{ auth.user ? "进入工作台" : "开始使用" }}
          </router-link>
          <router-link class="site-btn ghost" to="/blog">阅读研究</router-link>
        </div>
      </div>
    </section>

    <section class="sol-band">
      <div class="site-wrap">
        <div class="sol-head">
          <p class="site-kicker">Solutions</p>
          <h3>面向运营、研究与补丁验证</h3>
        </div>
        <div class="sol-grid">
          <article>
            <span>SOC</span>
            <strong>从公告到可执行检测</strong>
            <p>版本身份、哈希、IOC 与在野利用状态（含 CISA KEV 对照）进入同一份报告，给值班、资产清点和规则落地。</p>
          </article>
          <article>
            <span>Research</span>
            <strong>补丁归因到函数与检查点</strong>
            <p>用 PDB、.pdata 尺寸差、反汇编与 CFG 定位热点路径。证据不足标 unknown，RVA 与函数名均来自符号与反汇编。</p>
          </article>
          <article>
            <span>Patch Mgmt</span>
            <strong>判断修了没有、修全没有</strong>
            <p>输出绕过面、Feature 关闭路径和未改兄弟函数，判断补丁是闭合、部分闭合，还是仍有同类残留。</p>
          </article>
        </div>
      </div>
    </section>

    <section id="product" class="plat-band">
      <div class="site-wrap">
        <div class="plat-head">
          <p class="site-kicker">Platform</p>
          <h3>Windows 补丁情报与漏洞运营平台</h3>
          <p>
            对齐 MSRC 漏洞版与修复版二进制，把 Patch Tuesday 落到可核对的根因、检测与补丁完整性判断。
            SOC、漏洞研究与补丁验证共用同一份证据链。
          </p>
        </div>
        <div class="plat-grid">
          <article>
            <span>01</span>
            <strong>补丁日摄入</strong>
            <p>MSRC 月度公告选 CVE，自动解析漏洞版 / 修复版驱动对；也支持上传成对或三份样本。</p>
          </article>
          <article>
            <span>02</span>
            <strong>样本与版本对齐</strong>
            <p>PE 身份、FileVersion、Winbindex / MSDL 构建号对齐，避免 KB 与二进制对不上导致的误判。</p>
          </article>
          <article>
            <span>03</span>
            <strong>补丁热点定位</strong>
            <p>符号尺寸、Feature xref、代码节差异交叉筛选，把变更落到具体函数。</p>
          </article>
          <article>
            <span>04</span>
            <strong>根因与漏洞链</strong>
            <p>多专家流水线还原触发条件、内核路径、原语与切断点。结论旁标注已证实 / 推断。</p>
          </article>
          <article>
            <span>05</span>
            <strong>威胁情报对照</strong>
            <p>CVE 描述、在野报道与 KEV 目录对照 diff 证据，区分公开细节、目录命中和推断。</p>
          </article>
          <article>
            <span>06</span>
            <strong>检测与完整性</strong>
            <p>19 节中文报告含 IOC、绕过面、残留同类路径。可导出 PDF / HTML / Markdown 与 JSON 证据包。</p>
          </article>
        </div>
        <ul class="plat-out">
          <li>执行摘要</li>
          <li>漏洞链</li>
          <li>IOC / 检测方法</li>
          <li>在野利用</li>
          <li>补丁完整性</li>
          <li>残留漏洞</li>
        </ul>
      </div>
    </section>

    <section id="method" class="how-band">
      <div class="site-wrap">
        <div class="how-head">
          <p class="site-kicker">How it works</p>
          <h3>分析流水线</h3>
          <p>固定工具节点在前，专家取证在后。每一步可回溯到样本、符号和反汇编。</p>
        </div>
        <div class="how-grid">
          <article>
            <span>01</span>
            <strong>摄入</strong>
            <p>MSRC Patch Tuesday 选 CVE，或上传成对 / 三份驱动样本。</p>
          </article>
          <article>
            <span>02</span>
            <strong>对照</strong>
            <p>PE 身份、PDB、符号尺寸、Feature xref、代码节差异，选出热点函数。</p>
          </article>
          <article>
            <span>03</span>
            <strong>分析</strong>
            <p>反汇编、CFG、多专家取证。证据不够就调白名单工具，结论绑定到已采集的地址与函数名。</p>
          </article>
          <article>
            <span>04</span>
            <strong>交付</strong>
            <p>中文 19 节报告：摘要、根因、漏洞链、IOC、在野、绕过面、残留。可导出 PDF / HTML / Markdown。</p>
          </article>
        </div>
      </div>
    </section>

    <section class="news-band">
      <div class="site-wrap">
        <div class="news-head">
          <p class="site-kicker">Research</p>
          <h3>最新研究</h3>
          <router-link class="news-all" to="/blog">查看全部</router-link>
        </div>
        <p v-if="loading" class="site-empty">正在读取已发布报告…</p>
        <p v-else-if="!posts.length" class="site-empty">还没有对外发布的报告。登录工作台后，可把已完成任务的报告发到这里。</p>
        <div v-else class="news-grid">
          <router-link v-for="p in posts" :key="p.id" class="news-card" :to="`/blog/${p.slug}`">
            <div class="news-meta">
              <span v-if="p.cve">{{ p.cve }}</span>
              <span v-if="p.published_at">{{ fmtDate(p.published_at) }}</span>
            </div>
            <h4>{{ p.title }}</h4>
            <p>{{ p.excerpt }}</p>
            <span class="news-more">阅读全文</span>
          </router-link>
        </div>
      </div>
    </section>
  </div>
</template>
<script setup>
import { onMounted, ref } from "vue";
import { apiGet, fmtDate } from "../lib/api.js";
import { auth } from "../lib/auth.js";

const posts = ref([]);
const loading = ref(true);

onMounted(async () => {
  try {
    const data = await apiGet("/public/blog?limit=3");
    posts.value = data.items || [];
  } catch {
    posts.value = [];
  } finally {
    loading.value = false;
  }
});
</script>
