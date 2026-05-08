package engine

import (
	"testing"
)

func TestPartitionTargets_Empty(t *testing.T) {
	partitions := PartitionTargets(nil, 256)
	if len(partitions) != 0 {
		t.Errorf("空目标应返回空分片, got %d", len(partitions))
	}
}

func TestPartitionTargets_SameSubnet(t *testing.T) {
	targets := []*Target{
		{IP: "192.168.1.1", Port: 80},
		{IP: "192.168.1.2", Port: 80},
		{IP: "192.168.1.3", Port: 80},
	}

	partitions := PartitionTargets(targets, 256)
	if len(partitions) != 1 {
		t.Errorf("同/24网段应归为1个分片, got %d", len(partitions))
	}
	if len(partitions[0].Targets) != 3 {
		t.Errorf("分片应包含3个目标, got %d", len(partitions[0].Targets))
	}
}

func TestPartitionTargets_DifferentSubnets(t *testing.T) {
	targets := []*Target{
		{IP: "192.168.1.1"},
		{IP: "10.0.0.1"},
		{IP: "172.16.0.1"},
	}

	partitions := PartitionTargets(targets, 256)
	if len(partitions) != 3 {
		t.Errorf("不同网段应分为3个分片, got %d", len(partitions))
	}
}

func TestPartitionTargets_LargeGroupSplit(t *testing.T) {
	targets := make([]*Target, 300)
	for i := range targets {
		targets[i] = &Target{IP: "192.168.1.1", Port: i + 1}
	}

	partitions := PartitionTargets(targets, 100)
	if len(partitions) < 3 {
		t.Errorf("300个目标/100上限应至少分为3片, got %d", len(partitions))
	}
}

func TestPartitionTargets_DomainGrouping(t *testing.T) {
	targets := []*Target{
		{Host: "www.example.com"},
		{Host: "api.example.com"},
		{Host: "blog.other.org"},
	}

	partitions := PartitionTargets(targets, 256)
	if len(partitions) < 2 {
		t.Errorf("不同域名应分为不同分片, got %d", len(partitions))
	}
}

func TestPartitionTargets_SortedBySize(t *testing.T) {
	targets := []*Target{
		{IP: "10.0.0.1"},
		{IP: "192.168.1.1"},
		{IP: "192.168.1.2"},
		{IP: "192.168.1.3"},
	}

	partitions := PartitionTargets(targets, 256)
	if len(partitions) < 2 {
		t.Fatal("应至少2个分片")
	}
	if len(partitions[0].Targets) < len(partitions[len(partitions)-1].Targets) {
		t.Error("分片应按目标数量降序排列")
	}
}

func TestPartitionByProtocol(t *testing.T) {
	targets := []*Target{
		{Host: "a.com", Protocol: "tcp"},
		{Host: "b.com", Protocol: "udp"},
		{Host: "c.com", Protocol: "tcp"},
		{Host: "d.com"},
	}

	groups := PartitionByProtocol(targets)
	if len(groups["tcp"]) != 3 {
		t.Errorf("TCP组应有3个(含空protocol默认归入tcp), got %d", len(groups["tcp"]))
	}
	if len(groups["udp"]) != 1 {
		t.Errorf("UDP组应有1个, got %d", len(groups["udp"]))
	}
	if len(groups) != 2 {
		t.Errorf("应只有2个协议组, got %d", len(groups))
	}
}

func TestClassifyTarget_IPv6(t *testing.T) {
	target := &Target{IP: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}
	key := classifyTarget(target)
	if key == "" || key == "unknown" {
		t.Errorf("IPv6 分类不应为空/unknown, got %q", key)
	}
}

func TestClassifyTarget_NoInfo(t *testing.T) {
	target := &Target{}
	key := classifyTarget(target)
	if key != "unknown" {
		t.Errorf("无信息目标应为 unknown, got %q", key)
	}
}
