import type { ModuleDef } from '#/api/monitor';

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
    name: '暗链检测规则',
    type: 'engine',
    kv_key: 'engine/blacklink',
    description: '暗链/行业违规词/编码绕过检测正则',
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
    ],
  },
  malware: {
    key: 'malware',
    name: '恶意脚本规则',
    type: 'engine',
    kv_key: 'engine/malware',
    description: 'JS恶意脚本/挖矿/重定向/WebShell/Fetch检测',
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
  backdoor: {
    key: 'backdoor',
    name: '后门检测规则',
    type: 'engine',
    kv_key: 'engine/backdoor',
    description: '后门/WebShell检测正则',
    sections: [
      { key: 'rules', label: '检测正则', fields: [
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
  backdoor_path: {
    key: 'backdoor_path',
    name: '后门路径字典',
    type: 'dict',
    kv_key: 'data/backdoor_paths',
    description: '常见后门/敏感路径',
    sections: [
      { key: 'entries', label: '路径列表', fields: [
        { key: 'path', label: '路径', required: true, type: 'string' },
        { key: 'mark', label: '标记说明', required: false, type: 'string' },
        { key: 'risk', label: '风险等级', required: false, type: 'risk' },
      ]},
    ],
  },
  malicious_domain: {
    key: 'malicious_domain',
    name: '恶意域名',
    type: 'dict',
    kv_key: 'data/malicious_domains',
    description: '挖矿/C2/钓鱼/恶意广告/SEO垃圾域名黑名单',
    sections: [
      { key: 'miner', label: '挖矿域名', fields: [{ key: 'domain', label: '域名', required: true, type: 'string' }]},
      { key: 'c2', label: 'C2域名', fields: [{ key: 'domain', label: '域名', required: true, type: 'string' }]},
      { key: 'phishing', label: '钓鱼域名', fields: [{ key: 'domain', label: '域名', required: true, type: 'string' }]},
      { key: 'malvertising', label: '恶意广告', fields: [{ key: 'domain', label: '域名', required: true, type: 'string' }]},
      { key: 'seo_spam', label: 'SEO垃圾', fields: [{ key: 'domain', label: '域名', required: true, type: 'string' }]},
      { key: 'generic', label: '通用恶意', fields: [{ key: 'domain', label: '域名', required: true, type: 'string' }]},
    ],
  },
};
