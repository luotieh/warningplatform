package main

import (
	"flag"
	"fmt"
	"os"

	"vulnscan-backend/pkg/nodeenroll"
)

func runEnroll(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	out := fs.String("out", "node-enrollment.json", "注册 JSON 输出路径（私钥写入同名 .key，仅保留在本机）")
	fs.Usage = func() { printEnrollHelp() }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := nodeenroll.WriteEnrollmentBundle(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	key := nodeenroll.EnrollmentKeyPath(*out)
	fmt.Fprintf(os.Stderr, "已写入 %s\n已写入 %s（请勿上传；decrypt-credentials 时需要）\n", *out, key)
	return 0
}
