<script lang="ts" setup>
import { computed } from 'vue';

import { GraphChart } from 'echarts/charts';
import { LegendComponent, TooltipComponent } from 'echarts/components';
import { use } from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import VChart from 'vue-echarts';

use([CanvasRenderer, GraphChart, TooltipComponent, LegendComponent]);

interface Finding {
  type: string;
  title: string;
  data?: Record<string, string>;
  target?: string;
  confidence?: number;
}

const props = defineProps<{
  findings: Finding[];
  height?: string;
}>();

interface TopoNode {
  name: string;
  category: number;
  symbolSize: number;
  label?: { show: boolean };
  itemStyle?: { color: string };
  value?: string;
}

interface TopoLink {
  source: string;
  target: string;
  label?: { show: boolean; formatter: string };
  lineStyle?: { width: number; curveness: number; type: string };
  value?: string;
}

const categories = [
  { name: '扫描源', itemStyle: { color: '#3182ce' } },
  { name: '网关/路由', itemStyle: { color: '#805ad5' } },
  { name: '目标主机', itemStyle: { color: '#e53e3e' } },
  { name: 'CDN', itemStyle: { color: '#38b2ac' } },
  { name: '负载均衡', itemStyle: { color: '#d69e2e' } },
  { name: 'DNS服务器', itemStyle: { color: '#dd6b20' } },
  { name: 'IP地址', itemStyle: { color: '#718096' } },
  { name: 'CNAME', itemStyle: { color: '#667eea' } },
];

const chartOption = computed(() => {
  const nodes = new Map<string, TopoNode>();
  const links: TopoLink[] = [];
  const targetHosts = new Set<string>();

  for (const f of props.findings) {
    const host = f.data?.host || f.target || '';
    if (host) targetHosts.add(host);
  }

  // Add scanner node
  nodes.set('扫描器', {
    name: '扫描器',
    category: 0,
    symbolSize: 50,
    label: { show: true },
    itemStyle: { color: '#3182ce' },
  });

  // Process traceroute findings
  for (const f of props.findings) {
    if (f.type !== 'traceroute' || !f.data?.hops) continue;

    const targetIP = f.data.target_ip || '';
    const host = f.data.host || '';

    // Add target node
    const targetLabel = host && host !== targetIP ? `${host}\n${targetIP}` : targetIP;
    if (targetIP && !nodes.has(targetLabel)) {
      nodes.set(targetLabel, {
        name: targetLabel,
        category: 2,
        symbolSize: 45,
        label: { show: true },
        itemStyle: { color: '#e53e3e' },
      });
    }

    const hops = f.data.hops.split('|');
    let prevNode = '扫描器';

    for (const hopStr of hops) {
      const parts = hopStr.split(':');
      const ttl = parts[0];
      const ip = parts[1];

      if (!ip || ip === '*') continue;

      const rtt = parts[2] || '';
      const hopLabel = ip;

      if (!nodes.has(hopLabel)) {
        const isTarget = ip === targetIP;
        nodes.set(hopLabel, {
          name: hopLabel,
          category: isTarget ? 2 : 1,
          symbolSize: isTarget ? 45 : 28,
          label: { show: true },
          itemStyle: { color: isTarget ? '#e53e3e' : '#805ad5' },
          value: `TTL ${ttl}`,
        });
      }

      links.push({
        source: prevNode,
        target: hopLabel,
        label: {
          show: Boolean(rtt),
          formatter: rtt || '',
        },
        lineStyle: { width: 2, curveness: 0.1, type: 'solid' },
        value: `TTL ${ttl}${rtt ? ' - ' + rtt : ''}`,
      });

      prevNode = hopLabel;
    }

    // Link last hop to target if different
    if (prevNode !== targetLabel && targetLabel) {
      links.push({
        source: prevNode,
        target: targetLabel,
        lineStyle: { width: 2, curveness: 0.1, type: 'solid' },
      });
    }
  }

  // Process DNS findings
  for (const f of props.findings) {
    const host = f.data?.host || f.target || '';

    if (f.type === 'dns_cname' && f.data?.cname) {
      const cname = f.data.cname;
      if (!nodes.has(host)) {
        nodes.set(host, {
          name: host,
          category: 2,
          symbolSize: 40,
          label: { show: true },
          itemStyle: { color: '#e53e3e' },
        });
      }
      if (!nodes.has(cname)) {
        nodes.set(cname, {
          name: cname,
          category: 7,
          symbolSize: 30,
          label: { show: true },
          itemStyle: { color: '#667eea' },
        });
      }
      links.push({
        source: host,
        target: cname,
        label: { show: true, formatter: 'CNAME' },
        lineStyle: { width: 1.5, curveness: 0.2, type: 'dashed' },
      });
    }

    if (f.type === 'dns_multi_ip' && f.data?.ips) {
      if (!nodes.has(host)) {
        nodes.set(host, {
          name: host,
          category: 2,
          symbolSize: 40,
          label: { show: true },
          itemStyle: { color: '#e53e3e' },
        });
      }
      for (const ip of f.data.ips.split(',')) {
        const trimmedIP = ip.trim();
        if (!trimmedIP) continue;
        if (!nodes.has(trimmedIP)) {
          nodes.set(trimmedIP, {
            name: trimmedIP,
            category: 6,
            symbolSize: 24,
            label: { show: true },
            itemStyle: { color: '#718096' },
          });
        }
        links.push({
          source: host,
          target: trimmedIP,
          lineStyle: { width: 1, curveness: 0.15, type: 'dashed' },
          label: { show: true, formatter: 'A' },
        });
      }
    }

    if (f.type === 'dns_nameservers' && f.data?.nameservers) {
      if (!nodes.has(host)) {
        nodes.set(host, {
          name: host,
          category: 2,
          symbolSize: 40,
          label: { show: true },
          itemStyle: { color: '#e53e3e' },
        });
      }
      for (const ns of f.data.nameservers.split(',')) {
        const trimmedNS = ns.trim();
        if (!trimmedNS) continue;
        if (!nodes.has(trimmedNS)) {
          nodes.set(trimmedNS, {
            name: trimmedNS,
            category: 5,
            symbolSize: 26,
            label: { show: true },
            itemStyle: { color: '#dd6b20' },
          });
        }
        links.push({
          source: host,
          target: trimmedNS,
          lineStyle: { width: 1, curveness: 0.2, type: 'dotted' },
          label: { show: true, formatter: 'NS' },
        });
      }
    }

    if (f.type === 'cdn_detected' && f.data?.cdn) {
      const cdnName = `CDN: ${f.data.cdn}`;
      if (!nodes.has(host)) {
        nodes.set(host, {
          name: host,
          category: 2,
          symbolSize: 40,
          label: { show: true },
          itemStyle: { color: '#e53e3e' },
        });
      }
      if (!nodes.has(cdnName)) {
        nodes.set(cdnName, {
          name: cdnName,
          category: 3,
          symbolSize: 35,
          label: { show: true },
          itemStyle: { color: '#38b2ac' },
        });
      }
      links.push({
        source: '扫描器',
        target: cdnName,
        lineStyle: { width: 2, curveness: 0.2, type: 'solid' },
      });
      links.push({
        source: cdnName,
        target: host,
        lineStyle: { width: 2, curveness: 0.2, type: 'solid' },
        label: { show: true, formatter: 'CDN代理' },
      });
    }

    if (f.type === 'load_balancer_detected' && f.data?.servers) {
      const lbName = `LB: ${host}`;
      if (!nodes.has(lbName)) {
        nodes.set(lbName, {
          name: lbName,
          category: 4,
          symbolSize: 35,
          label: { show: true },
          itemStyle: { color: '#d69e2e' },
        });
      }
      for (const srv of f.data.servers.split(',')) {
        const srvName = `Server: ${srv.trim()}`;
        if (!nodes.has(srvName)) {
          nodes.set(srvName, {
            name: srvName,
            category: 2,
            symbolSize: 28,
            label: { show: true },
            itemStyle: { color: '#e53e3e' },
          });
        }
        links.push({
          source: lbName,
          target: srvName,
          lineStyle: { width: 1.5, curveness: 0.15, type: 'solid' },
        });
      }
      links.push({
        source: '扫描器',
        target: lbName,
        lineStyle: { width: 2, curveness: 0.1, type: 'solid' },
        label: { show: true, formatter: '负载均衡' },
      });
    }

    if (f.type === 'reverse_dns' && f.data?.names && f.data?.ip) {
      const ip = f.data.ip;
      if (!nodes.has(ip)) {
        nodes.set(ip, {
          name: ip,
          category: 6,
          symbolSize: 28,
          label: { show: true },
          itemStyle: { color: '#718096' },
        });
      }
      for (const name of f.data.names.split(',')) {
        const trimmedName = name.trim();
        if (!trimmedName) continue;
        if (!nodes.has(trimmedName)) {
          nodes.set(trimmedName, {
            name: trimmedName,
            category: 7,
            symbolSize: 24,
            label: { show: true },
            itemStyle: { color: '#667eea' },
          });
        }
        links.push({
          source: ip,
          target: trimmedName,
          lineStyle: { width: 1, curveness: 0.2, type: 'dotted' },
          label: { show: true, formatter: 'PTR' },
        });
      }
    }
  }

  // Deduplicate links
  const linkSet = new Set<string>();
  const uniqueLinks = links.filter((l) => {
    const key = `${l.source}->${l.target}`;
    if (linkSet.has(key)) return false;
    linkSet.add(key);
    return true;
  });

  // Connect scanner to target hosts if no traceroute/CDN/LB link exists
  const linkedFromScanner = new Set(
    uniqueLinks.filter((l) => l.source === '扫描器').map((l) => l.target),
  );
  for (const host of targetHosts) {
    if (nodes.has(host) && !linkedFromScanner.has(host)) {
      const hasIndirectLink = uniqueLinks.some(
        (l) =>
          l.source === '扫描器' &&
          uniqueLinks.some((l2) => l2.source === l.target && l2.target === host),
      );
      if (!hasIndirectLink) {
        uniqueLinks.push({
          source: '扫描器',
          target: host,
          lineStyle: { width: 1.5, curveness: 0.1, type: 'dashed' },
        });
      }
    }
  }

  return {
    tooltip: {
      trigger: 'item',
      formatter: (params: any) => {
        if (params.dataType === 'edge') {
          return params.value || `${params.data.source} → ${params.data.target}`;
        }
        return `<b>${params.name}</b>${params.data?.value ? '<br/>' + params.data.value : ''}`;
      },
    },
    legend: {
      data: categories.map((c) => c.name),
      orient: 'horizontal',
      bottom: 10,
      textStyle: { fontSize: 11 },
    },
    series: [
      {
        type: 'graph',
        layout: 'force',
        animation: true,
        draggable: true,
        roam: true,
        zoom: 1.2,
        categories,
        data: Array.from(nodes.values()),
        links: uniqueLinks,
        label: {
          show: true,
          position: 'bottom',
          fontSize: 10,
          color: '#333',
        },
        edgeLabel: {
          show: true,
          fontSize: 9,
          color: '#999',
        },
        lineStyle: {
          color: '#aaa',
          opacity: 0.7,
        },
        emphasis: {
          focus: 'adjacency',
          lineStyle: { width: 4 },
        },
        force: {
          repulsion: 400,
          edgeLength: [80, 200],
          gravity: 0.1,
          layoutAnimation: true,
        },
      },
    ],
  };
});

const hasData = computed(() => {
  return props.findings.some((f) =>
    [
      'traceroute',
      'network_gateway',
      'dns_multi_ip',
      'dns_cname',
      'dns_nameservers',
      'reverse_dns',
      'cdn_detected',
      'load_balancer_detected',
    ].includes(f.type),
  );
});
</script>

<template>
  <div v-if="hasData" :style="{ height: height ?? '550px', width: '100%' }">
    <VChart :option="chartOption" autoresize />
  </div>
  <div
    v-else
    style="
      text-align: center;
      padding: 60px 0;
      color: #999;
      font-size: 14px;
    "
  >
    暂无网络拓扑数据，请确保扫描任务包含网络拓扑探测模块
  </div>
</template>
