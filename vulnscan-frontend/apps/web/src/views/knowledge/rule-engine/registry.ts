import type { ModuleDef } from '#/api/sitemonitor';

export const MODULE_REGISTRY: Record<string, ModuleDef> = {
  availability: {
    key: 'availability',
    name: '可用性检测规则',
    type: 'engine',
    kv_key: 'engine/availability',
    description: 'TLS/证书/安全头/信息泄露检测规则',
    sections: [
      { key: 'tls_ciphers', label: 'TLS密码套件', fields: [
        { key: 'name', label: '名称', required: true, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
        { key: 'severity', label: '等级', required: false, type: 'severity' },
      ]},
      { key: 'tls_versions', label: 'TLS版本', fields: [
        { key: 'name', label: '名称', required: true, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
        { key: 'severity', label: '等级', required: false, type: 'severity' },
      ]},
      { key: 'cert_check', label: '证书检查', fields: [
        { key: 'name', label: '名称', required: true, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
        { key: 'severity', label: '等级', required: false, type: 'severity' },
      ]},
      { key: 'http_headers_check', label: 'HTTP安全头', fields: [
        { key: 'name', label: '名称', required: true, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
        { key: 'severity', label: '等级', required: false, type: 'severity' },
      ]},
      { key: 'info_leak_headers', label: '信息泄露头', fields: [
        { key: 'name', label: '名称', required: true, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
        { key: 'severity', label: '等级', required: false, type: 'severity' },
      ]},
    ],
  },
  domain_hijack: {
    key: 'domain_hijack',
    name: '域名劫持规则',
    type: 'engine',
    kv_key: 'engine/domain_hijack',
    description: '域名劫持检测模式',
    sections: [
      { key: 'hijack_patterns', label: '劫持检测模式', fields: [
        { key: 'pattern', label: '正则表达式', required: true, type: 'regex' },
        { key: 'name', label: '名称', required: true, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
        { key: 'severity', label: '等级', required: false, type: 'severity' },
      ]},
      { key: 'hijack_titles', label: '劫持页面标题', fields: [
        { key: 'title', label: '标题关键词', required: true, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
      ]},
      { key: 'parking_ips', label: '停靠/沉洞IP', fields: [
        { key: 'ip', label: 'IP地址', required: true, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
      ]},
    ],
  },
  tamper: {
    key: 'tamper',
    name: '篡改检测规则',
    type: 'engine',
    kv_key: 'engine/tamper',
    description: '篡改噪声过滤、动态内容选择器和可信域名',
    sections: [
      { key: 'noise_patterns', label: '噪声过滤正则', fields: [
        { key: 'pattern', label: '正则表达式', required: true, type: 'regex' },
        { key: 'description', label: '描述', required: false, type: 'string' },
      ]},
      { key: 'dynamic_selectors', label: '动态内容选择器', fields: [
        { key: 'selector', label: 'CSS选择器', required: true, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
      ]},
      { key: 'trusted_domains', label: '可信域名', fields: [
        { key: 'domain', label: '域名', required: true, type: 'string' },
        { key: 'mark', label: '标记说明', required: false, type: 'string' },
      ]},
    ],
  },
  blacklink: {
    key: 'blacklink',
    name: '暗链/后门检测',
    type: 'engine',
    kv_key: 'engine/blacklink',
    description: '暗链 URL 规则、行业黑词、编码绕过、后门代码特征、后门路径字典',
    sections: [
      { key: 'rules', label: '暗链检测正则', fields: [
        { key: 're', label: '正则表达式', required: true, type: 'regex' },
        { key: 'mark', label: '标记说明', required: false, type: 'string' },
      ]},
      { key: 'industry_blackwords', label: '行业违规词', fields: [
        { key: 're', label: '正则表达式', required: true, type: 'regex' },
        { key: 'mark', label: '标记说明', required: false, type: 'string' },
      ]},
      { key: 'encoded_href_patterns', label: '编码绕过检测', fields: [
        { key: 're', label: '正则表达式', required: true, type: 'regex' },
        { key: 'mark', label: '标记说明', required: false, type: 'string' },
      ]},
      { key: 'backdoor_code_rules', label: '后门代码特征', fields: [
        { key: 're', label: '正则表达式', required: true, type: 'regex' },
        { key: 'mark', label: '标记说明', required: false, type: 'string' },
      ]},
      { key: 'backdoor_paths', label: '后门路径字典', fields: [
        { key: 'path', label: '路径', required: true, type: 'string' },
        { key: 'mark', label: '标记说明', required: false, type: 'string' },
        { key: 'risk', label: '风险等级', required: false, type: 'risk' },
      ]},
    ],
  },
  malware: {
    key: 'malware',
    name: '恶意代码检测',
    type: 'engine',
    kv_key: 'engine/malware',
    description: 'JS 恶意脚本、挖矿、恶意跳转、WebShell、恶意域名库',
    sections: [
      { key: 'js_malicious_patterns', label: 'JS恶意脚本', fields: [
        { key: 'pattern', label: '正则表达式', required: true, type: 'regex' },
        { key: 'name', label: '名称', required: false, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
        { key: 'severity', label: '等级', required: false, type: 'severity' },
      ]},
      { key: 'miner_patterns', label: '挖矿脚本', fields: [
        { key: 'pattern', label: '正则表达式', required: true, type: 'regex' },
        { key: 'name', label: '名称', required: false, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
        { key: 'severity', label: '等级', required: false, type: 'severity' },
      ]},
      { key: 'redirect_patterns', label: '恶意重定向', fields: [
        { key: 'pattern', label: '正则表达式', required: true, type: 'regex' },
        { key: 'name', label: '名称', required: false, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
        { key: 'severity', label: '等级', required: false, type: 'severity' },
      ]},
      { key: 'webshell_patterns', label: 'WebShell', fields: [
        { key: 'pattern', label: '正则表达式', required: true, type: 'regex' },
        { key: 'name', label: '名称', required: false, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
        { key: 'severity', label: '等级', required: false, type: 'severity' },
      ]},
      { key: 'fetch_patterns', label: 'Fetch检测', fields: [
        { key: 'pattern', label: '正则表达式', required: true, type: 'regex' },
        { key: 'name', label: '名称', required: false, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
        { key: 'severity', label: '等级', required: false, type: 'severity' },
      ]},
      { key: 'malicious_domains_miner', label: '挖矿域名', fields: [{ key: 'domain', label: '域名', required: true, type: 'string' }]},
      { key: 'malicious_domains_c2', label: 'C2域名', fields: [{ key: 'domain', label: '域名', required: true, type: 'string' }]},
      { key: 'malicious_domains_phishing', label: '钓鱼域名', fields: [{ key: 'domain', label: '域名', required: true, type: 'string' }]},
      { key: 'malicious_domains_malvertising', label: '恶意广告域名', fields: [{ key: 'domain', label: '域名', required: true, type: 'string' }]},
      { key: 'malicious_domains_seo_spam', label: 'SEO垃圾域名', fields: [{ key: 'domain', label: '域名', required: true, type: 'string' }]},
      { key: 'malicious_domains_generic', label: '通用恶意域名', fields: [{ key: 'domain', label: '域名', required: true, type: 'string' }]},
    ],
  },
  sf_engine: {
    key: 'sf_engine',
    name: '敏感文件引擎',
    type: 'engine',
    kv_key: 'engine/sensitive_file',
    description: '敏感文件内容检测模式/soft404/备份变体',
    sections: [
      { key: 'content_patterns', label: '内容检测模式', fields: [
        { key: 'pattern', label: '正则表达式', required: true, type: 'regex' },
        { key: 'name', label: '名称', required: false, type: 'string' },
        { key: 'severity', label: '等级', required: false, type: 'severity' },
      ]},
      { key: 'soft_404_patterns', label: 'Soft 404检测', fields: [
        { key: 'pattern', label: '正则表达式', required: true, type: 'regex' },
        { key: 'description', label: '描述', required: false, type: 'string' },
      ]},
      { key: 'backup_variants', label: '备份文件后缀', fields: [
        { key: 'suffix', label: '后缀', required: true, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
      ]},
      { key: 'high_risk_dirs', label: '高风险目录', fields: [
        { key: 'path', label: '目录路径', required: true, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
      ]},
      { key: 'safe_files', label: '安全文件白名单', fields: [
        { key: 'name', label: '文件名', required: true, type: 'string' },
        { key: 'description', label: '描述', required: false, type: 'string' },
      ]},
    ],
  },
  sw_engine: {
    key: 'sw_engine',
    name: '敏感词引擎',
    type: 'engine',
    kv_key: 'engine/sensitive_word',
    description: '违规链接检测正则',
    sections: [
      { key: 'violativelink_rules', label: '违规链接正则', fields: [
        { key: 're', label: '正则表达式', required: true, type: 'regex' },
        { key: 'mark', label: '标记说明', required: false, type: 'string' },
      ]},
    ],
  },
  common: {
    key: 'common',
    name: '公共配置',
    type: 'engine',
    kv_key: 'engine/common',
    description: '公共DNS等共享配置',
    sections: [
      { key: 'public_dns', label: '公共DNS', fields: [
        { key: 'ip', label: 'IP地址', required: true, type: 'string' },
        { key: 'name', label: '名称', required: true, type: 'string' },
      ]},
    ],
  },
  whiteip: {
    key: 'whiteip',
    name: 'IP白名单',
    type: 'dict',
    kv_key: 'data/whiteips',
    description: 'CDN/内网等可信IP',
    sections: [
      { key: 'entries', label: '白名单', fields: [
        { key: 'domain', label: '域名/IP', required: true, type: 'string' },
        { key: 'mark', label: '标记说明', required: false, type: 'string' },
      ]},
    ],
  },
};
