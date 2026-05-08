package compliance

func CISLinuxLevel1() *Framework {
	return &Framework{
		ID:          "cis-linux-l1",
		Name:        "CIS Linux Benchmark Level 1",
		Version:     "3.0.0",
		Description: "CIS Linux基线检查 Level 1",
		Standard:    "CIS",
		Rules: []Rule{
			{
				ID: "cis-1.1.1", Category: "filesystem",
				Title: "确保/tmp使用独立分区", Severity: "medium",
				CheckType:   CheckTypeCommand,
				CheckConfig: CheckConfig{Command: "mount | grep ' /tmp '", Expected: "/tmp", Comparator: ComparatorContains},
				Remediation: "编辑 /etc/fstab 为 /tmp 配置独立分区",
			},
			{
				ID: "cis-1.4.1", Category: "bootloader",
				Title: "确保GRUB设置密码", Severity: "high",
				CheckType:   CheckTypeFile,
				CheckConfig: CheckConfig{FilePath: "/boot/grub2/grub.cfg", FileMatch: "password", Expected: "password", Comparator: ComparatorContains},
				Remediation: "执行 grub2-setpassword 设置引导密码",
			},
			{
				ID: "cis-3.1.1", Category: "network",
				Title: "确保IP转发关闭", Severity: "medium",
				CheckType:   CheckTypeCommand,
				CheckConfig: CheckConfig{Command: "sysctl net.ipv4.ip_forward", Expected: "0", Comparator: ComparatorContains},
				Remediation: "sysctl -w net.ipv4.ip_forward=0",
			},
			{
				ID: "cis-4.2.1", Category: "logging",
				Title: "确保rsyslog已安装", Severity: "medium",
				CheckType:   CheckTypeCommand,
				CheckConfig: CheckConfig{Command: "rpm -q rsyslog || dpkg -l rsyslog", Expected: "rsyslog", Comparator: ComparatorContains},
				Remediation: "yum install rsyslog 或 apt install rsyslog",
			},
			{
				ID: "cis-5.2.1", Category: "ssh",
				Title: "确保SSH协议版本为2", Severity: "high",
				CheckType:   CheckTypeCommand,
				CheckConfig: CheckConfig{Command: "sshd -T | grep protocol", Expected: "2", Comparator: ComparatorContains},
				Remediation: "设置 /etc/ssh/sshd_config 中 Protocol 2",
			},
			{
				ID: "cis-5.2.2", Category: "ssh",
				Title: "确保SSH MaxAuthTries ≤ 4", Severity: "medium",
				CheckType:   CheckTypeCommand,
				CheckConfig: CheckConfig{Command: "sshd -T | grep maxauthtries", Expected: "4", Comparator: ComparatorLTE},
				Remediation: "设置 MaxAuthTries 4",
			},
			{
				ID: "cis-5.4.1", Category: "account",
				Title: "确保密码过期天数 ≤ 365", Severity: "medium",
				CheckType:   CheckTypeCommand,
				CheckConfig: CheckConfig{Command: "grep PASS_MAX_DAYS /etc/login.defs | grep -v '#' | awk '{print $2}'", Expected: "365", Comparator: ComparatorLTE},
				Remediation: "编辑 /etc/login.defs 设置 PASS_MAX_DAYS 365",
			},
		},
	}
}

func DJCP2Level3() *Framework {
	return &Framework{
		ID:          "djcp2-l3",
		Name:        "等保2.0三级",
		Version:     "2.0",
		Description: "网络安全等级保护2.0三级基线",
		Standard:    "DJCP2",
		Rules: []Rule{
			{
				ID: "djcp-3.1.1", Category: "identity",
				Title: "身份鉴别-登录失败锁定", Severity: "high",
				CheckType:   CheckTypeCommand,
				CheckConfig: CheckConfig{Command: "grep pam_tally2 /etc/pam.d/system-auth", Expected: "deny=", Comparator: ComparatorContains},
				Remediation: "配置 pam_tally2 或 pam_faillock",
			},
			{
				ID: "djcp-3.1.2", Category: "identity",
				Title: "身份鉴别-密码复杂度", Severity: "high",
				CheckType:   CheckTypeCommand,
				CheckConfig: CheckConfig{Command: "grep pam_pwquality /etc/pam.d/system-auth", Expected: "pam_pwquality", Comparator: ComparatorContains},
				Remediation: "配置 pam_pwquality 策略",
			},
			{
				ID: "djcp-3.2.1", Category: "access_control",
				Title: "访问控制-最小权限", Severity: "high",
				CheckType:   CheckTypeCommand,
				CheckConfig: CheckConfig{Command: "cat /etc/passwd | awk -F: '($3==0){print $1}'", Expected: "root", Comparator: ComparatorEqual},
				Remediation: "确保只有root用户UID为0",
			},
			{
				ID: "djcp-3.3.1", Category: "audit",
				Title: "安全审计-审计功能开启", Severity: "high",
				CheckType:   CheckTypeCommand,
				CheckConfig: CheckConfig{Command: "systemctl is-active auditd", Expected: "active", Comparator: ComparatorEqual},
				Remediation: "systemctl enable --now auditd",
			},
			{
				ID: "djcp-3.4.1", Category: "intrusion",
				Title: "入侵防范-关闭非必要服务", Severity: "medium",
				CheckType:   CheckTypeCommand,
				CheckConfig: CheckConfig{Command: "systemctl is-active telnet.socket", Expected: "inactive", Comparator: ComparatorContains},
				Remediation: "systemctl stop telnet.socket && systemctl disable telnet.socket",
			},
		},
	}
}
