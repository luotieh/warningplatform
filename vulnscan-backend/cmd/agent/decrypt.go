package main

import (
	"flag"
	"fmt"
	"os"

	"vulnscan-backend/agent"
)

func runDecryptCredentials(args []string) int {
	fs := flag.NewFlagSet("decrypt-credentials", flag.ExitOnError)
	envPath := fs.String("envelope", "", "主控下发的加密信封 JSON 路径")
	keyPath := fs.String("key", "", "enroll 生成的 RSA 私钥 PEM 路径（.key）")
	outPath := fs.String("out", "node-agent.credentials.json", "解密后的明文凭证输出路径")
	fs.Usage = func() { printDecryptHelp() }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *envPath == "" || *keyPath == "" {
		fs.Usage()
		return 1
	}
	if err := agent.DecryptCredentialEnvelopeToFile(*envPath, *keyPath, *outPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "已写入 %s — 请在配置中设置 credentials_file 或环境变量 AGENT_CREDENTIALS_FILE，然后执行 run 启动 Agent。\n", *outPath)
	return 0
}
