<script lang="ts" setup>
import { Page } from '@vben/common-ui';
import { IconifyIcon } from '@vben/icons';
import { NCard, NGrid, NGi, NTag, NCollapse, NCollapseItem } from 'naive-ui';

defineOptions({ name: 'MonitorCapabilities' });

const props = withDefaults(defineProps<{ embedded?: boolean }>(), {
  embedded: false,
});

interface Detection {
  name: string;
  severity: string;
  desc: string;
}

interface Capability {
  dimension: string;
  icon: string;
  color: string;
  title: string;
  subtitle: string;
  detections: Detection[];
}

const capabilities: Capability[] = [
  {
    dimension: 'tamper',
    icon: 'ri:shield-check-line',
    color: '#ef4444',
    title: '网页篡改监测',
    subtitle: '多维度比对页面内容，智能区分恶意篡改与正常更新',
    detections: [
      { name: '内容哈希对比', severity: 'high', desc: '精确检测页面内容是否被修改' },
      { name: 'Simhash 相似度分析', severity: 'high', desc: '智能区分微调(>95%)、小改(>85%)、中改(>70%)、大改，降低误报' },
      { name: '标题变更检测', severity: 'medium', desc: '检测页面标题被篡改' },
      { name: '状态码异常', severity: 'high', desc: '检测页面返回码是否异常变化' },
      { name: '文本长度变化', severity: 'medium', desc: '超过30%的文字量变化触发告警' },
      { name: '外部脚本注入', severity: 'critical', desc: '检测是否被注入不受信任的外部JS脚本' },
      { name: '交叉验证（敏感词+暗链）', severity: 'critical', desc: '篡改时联动检测敏感词和暗链，确认恶意篡改' },
      { name: '正常更新自动接受', severity: 'info', desc: '无恶意内容的页面变更自动更新基线，减少人工干预' },
      { name: '基线置信度自动升级', severity: 'info', desc: '连续稳定3/7次后自动升级置信度等级' },
      { name: 'Wayback Machine 验证', severity: 'medium', desc: '利用互联网存档验证初始基线可信度' },
    ],
  },
  {
    dimension: 'blacklink',
    icon: 'ri:link-unlink-m',
    color: '#f97316',
    title: '暗链/挂马检测',
    subtitle: '全方位检测隐藏链接、恶意脚本注入和JS跳转行为',
    detections: [
      { name: '暗链规则匹配', severity: 'high', desc: '基于正则规则库匹配已知暗链模式' },
      { name: '隐藏链接检测', severity: 'high', desc: '检测CSS隐藏(display:none/visibility:hidden/opacity:0/负定位/零字体)的链接' },
      { name: '后门路径检测', severity: 'critical', desc: '检测Webshell等后门路径特征' },
      { name: '隐藏iframe检测', severity: 'high', desc: '检测外部域名的隐藏iframe(零尺寸、CSS隐藏)' },
      { name: 'JS即时跳转', severity: 'medium', desc: '检测location.href/replace/window.open等6种跳转模式' },
      { name: 'JS延迟跳转', severity: 'high', desc: '检测setTimeout/setInterval中的延迟跳转代码' },
      { name: '浏览器动态跳转检测', severity: 'high', desc: '用无头浏览器实际导航，等待5秒检测动态跳转' },
      { name: 'meta refresh跳转', severity: 'high', desc: '检测meta标签的外域跳转' },
      { name: '混淆eval执行', severity: 'critical', desc: '检测eval(unescape(...))等混淆代码执行' },
      { name: '动态写入script/iframe', severity: 'critical', desc: '检测document.write注入外部脚本/框架' },
      { name: '加密货币挖矿', severity: 'critical', desc: '检测CoinHive/CryptoNight等挖矿脚本' },
      { name: '十六进制/Unicode编码', severity: 'high', desc: '检测大量编码字符串(恶意代码隐藏手法)' },
      { name: 'CharCode解码', severity: 'high', desc: '检测String.fromCharCode大量解码(恶意代码特征)' },
      { name: 'SEO Cloaking检测', severity: 'critical', desc: '用Googlebot/Baiduspider/Bingbot三种UA对比，检测搜索引擎欺骗' },
    ],
  },
  {
    dimension: 'sensitive_word',
    icon: 'ri:file-warning-line',
    color: '#eab308',
    title: '敏感词监测',
    subtitle: '基于知识库词库和智能模式匹配，检测页面敏感内容和数据泄露',
    detections: [
      { name: '词库关键词匹配', severity: 'high', desc: '基于用户配置的敏感词库(支持分类/分级)进行全文匹配' },
      { name: '匹配上下文提取', severity: 'info', desc: '提取匹配词的上下文环境作为证据' },
      { name: '页面证据截图', severity: 'info', desc: '自动截图并高亮标注匹配的敏感词' },
      { name: '手机号检测', severity: 'high', desc: '检测中国大陆手机号(1[3-9]开头11位)' },
      { name: '身份证号检测', severity: 'critical', desc: '18位身份证号检测+校验码验证' },
      { name: '银行卡号检测', severity: 'critical', desc: '13-19位银行卡号+Luhn校验算法' },
      { name: '电子邮箱检测', severity: 'medium', desc: '检测页面中暴露的邮箱地址' },
      { name: '内网IP地址', severity: 'medium', desc: '检测10.x/172.16-31.x/192.168.x内网地址泄露' },
      { name: 'AWS密钥检测', severity: 'critical', desc: '检测AKIA/ABIA/ACCA/ASIA开头的AWS密钥' },
      { name: '私钥标记检测', severity: 'critical', desc: '检测RSA/EC/DSA私钥文件标记' },
      { name: '数据库连接串', severity: 'critical', desc: '检测mysql://、postgres://、mongodb://等连接串泄露' },
    ],
  },
  {
    dimension: 'availability',
    icon: 'ri:pulse-line',
    color: '#22c55e',
    title: '可用性监测',
    subtitle: '全面监控网站可达性、性能指标、安全配置和内容完整性',
    detections: [
      { name: 'HTTP状态码监控', severity: 'critical', desc: '检测5xx服务器错误和4xx客户端错误' },
      { name: '关键词存活验证', severity: 'high', desc: '检查页面是否包含预期关键词，防止被劫持到空白页' },
      { name: '空白劫持检测', severity: 'high', desc: '页面返回200但内容极少且无标题时告警' },
      { name: '跨域重定向检测', severity: 'high', desc: '检测页面被重定向到不同域名' },
      { name: 'meta外域跳转检测', severity: 'high', desc: '检测meta refresh指向外部域名' },
      { name: '安全头缺失检测', severity: 'medium', desc: '检查X-Frame-Options、CSP等安全头配置' },
      { name: 'SSL证书监控', severity: 'critical', desc: '检测证书过期、即将过期、弱TLS版本' },
      { name: 'TTFB性能监控', severity: 'medium', desc: 'TTFB超过5秒告警' },
      { name: '总响应时间监控', severity: 'high', desc: '总响应超过15秒告警' },
      { name: 'DNS解析异常', severity: 'medium', desc: 'DNS解析超过3秒告警' },
    ],
  },
  {
    dimension: 'domain_hijack',
    icon: 'ri:global-line',
    color: '#8b5cf6',
    title: '域名劫持检测',
    subtitle: '多DNS解析器交叉比对，检测DNS劫持和域名被盗',
    detections: [
      { name: '多DNS解析对比', severity: 'critical', desc: '使用多个公共DNS解析器对比结果，检测DNS劫持' },
      { name: 'Parking IP检测', severity: 'critical', desc: '检测域名是否解析到已知的域名停放/Sinkhole IP' },
      { name: '可疑CNAME检测', severity: 'high', desc: '检测CNAME指向可疑域名' },
      { name: '劫持标题特征', severity: 'high', desc: '检测页面标题匹配已知劫持特征词' },
      { name: 'DNS/TLS交叉验证', severity: 'medium', desc: '基线建立时进行DNS和TLS全面交叉验证' },
    ],
  },
  {
    dimension: 'sensitive_file',
    icon: 'ri:folder-shield-2-line',
    color: '#06b6d4',
    title: '敏感文件探测',
    subtitle: '主动探测Web服务器上暴露的敏感文件和配置泄露',
    detections: [
      { name: '环境变量泄露(.env)', severity: 'critical', desc: '检测.env文件暴露数据库密码等敏感配置' },
      { name: 'Git仓库泄露', severity: 'critical', desc: '检测.git/HEAD、.git/config等Git信息泄露' },
      { name: 'SVN泄露', severity: 'critical', desc: '检测.svn/entries等SVN信息泄露' },
      { name: 'Java配置泄露', severity: 'critical', desc: '检测WEB-INF/web.xml等Java应用配置暴露' },
      { name: 'WordPress配置', severity: 'critical', desc: '检测wp-config.php.bak等WordPress配置备份' },
      { name: 'PHP信息泄露', severity: 'high', desc: '检测phpinfo.php暴露的服务器信息' },
      { name: '目录遍历检测', severity: 'high', desc: '检测Apache/Nginx目录列表是否开启' },
      { name: 'WAF误报过滤', severity: 'info', desc: '智能识别WAF拦截页，避免将拦截页误判为敏感文件' },
      { name: '内容指纹分类', severity: 'info', desc: '20+种内容指纹规则（数据库凭证/密钥/Git/PHP/WordPress等）' },
      { name: '并发探测', severity: 'info', desc: '10并发探测，单次可检查80+条路径' },
      { name: '自定义路径库', severity: 'info', desc: '支持导入自定义敏感文件路径库' },
    ],
  },
];

const sevColorMap: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#16a34a',
  info: '#6366f1',
};

const sevLabelMap: Record<string, string> = {
  critical: '严重',
  high: '高',
  medium: '中',
  low: '低',
  info: '信息',
};

function getSeverityColor(sev: string): string {
  return sevColorMap[sev] || '#6b7280';
}

function getSeverityLabel(sev: string): string {
  return sevLabelMap[sev] || sev;
}
</script>

<template>
  <component
    :is="props.embedded ? 'div' : Page"
    v-bind="props.embedded ? {} : { title: '监测能力总览', description: '全面展示本平台六大安全监测维度的检测能力和覆盖范围' }"
  >
    <div class="capabilities-container">
      <div class="stats-summary">
        <div class="stat-item">
          <div class="stat-value">6</div>
          <div class="stat-label">监测维度</div>
        </div>
        <div class="stat-item">
          <div class="stat-value">
            {{ capabilities.reduce((sum, c) => sum + c.detections.length, 0) }}
          </div>
          <div class="stat-label">检测能力项</div>
        </div>
        <div class="stat-item">
          <div class="stat-value">
            {{ capabilities.reduce((sum, c) => sum + c.detections.filter(d => d.severity === 'critical').length, 0) }}
          </div>
          <div class="stat-label">严重级检测</div>
        </div>
        <div class="stat-item">
          <div class="stat-value">24/7</div>
          <div class="stat-label">持续监测</div>
        </div>
      </div>

      <NCollapse :default-expanded-names="capabilities.map(c => c.dimension)">
        <NCollapseItem
          v-for="cap in capabilities"
          :key="cap.dimension"
          :name="cap.dimension"
        >
          <template #header>
            <div class="cap-header">
              <span class="cap-icon" :style="{ color: cap.color, background: cap.color + '14' }">
                <IconifyIcon :icon="cap.icon" :size="20" />
              </span>
              <div class="cap-title-group">
                <span class="cap-title">{{ cap.title }}</span>
                <span class="cap-count">{{ cap.detections.length }} 项检测能力</span>
              </div>
            </div>
          </template>
          <template #header-extra>
            <NTag :bordered="false" size="small" :style="{ background: cap.color + '18', color: cap.color }">
              {{ cap.subtitle }}
            </NTag>
          </template>
          <div class="detection-grid">
            <NGrid :x-gap="12" :y-gap="12" cols="1 600:2 1000:3">
              <NGi v-for="det in cap.detections" :key="det.name">
                <NCard
                  size="small"
                  :bordered="true"
                  class="detection-card"
                  :style="{ borderLeftColor: getSeverityColor(det.severity) }"
                >
                  <div class="detection-header">
                    <span class="detection-name">{{ det.name }}</span>
                    <NTag
                      :bordered="false"
                      size="tiny"
                      :style="{
                        background: getSeverityColor(det.severity) + '18',
                        color: getSeverityColor(det.severity),
                      }"
                    >
                      {{ getSeverityLabel(det.severity) }}
                    </NTag>
                  </div>
                  <div class="detection-desc">{{ det.desc }}</div>
                </NCard>
              </NGi>
            </NGrid>
          </div>
        </NCollapseItem>
      </NCollapse>
    </div>
  </component>
</template>

<style scoped>
.capabilities-container {
  max-width: 1400px;
  margin: 0 auto;
}

.stats-summary {
  display: flex;
  gap: 24px;
  margin-bottom: 28px;
  padding: 24px 32px;
  background: linear-gradient(135deg, var(--card-color, #fff) 0%, rgba(99, 102, 241, 0.04) 100%);
  border: 1px solid var(--border-color, #e5e7eb);
  border-radius: 12px;
}

.stat-item {
  flex: 1;
  text-align: center;
}

.stat-value {
  font-size: 32px;
  font-weight: 700;
  color: var(--text-color-1, #111827);
  line-height: 1.2;
}

.stat-label {
  margin-top: 4px;
  font-size: 13px;
  color: var(--text-color-3, #9ca3af);
}

.cap-header {
  display: flex;
  align-items: center;
  gap: 12px;
}

.cap-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border-radius: 8px;
  flex-shrink: 0;
}

.cap-title-group {
  display: flex;
  align-items: baseline;
  gap: 8px;
}

.cap-title {
  font-size: 16px;
  font-weight: 600;
  color: var(--text-color-1, #111827);
}

.cap-count {
  font-size: 12px;
  color: var(--text-color-3, #9ca3af);
}

.detection-grid {
  padding: 4px 0;
}

.detection-card {
  border-left: 3px solid;
  transition: box-shadow 0.2s, transform 0.2s;
}

.detection-card:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
  transform: translateY(-1px);
}

.detection-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 6px;
}

.detection-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-color-1, #111827);
}

.detection-desc {
  font-size: 12px;
  color: var(--text-color-3, #6b7280);
  line-height: 1.5;
}
</style>
