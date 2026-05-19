package main

import (
	"fmt"
	"os"
)

func main() {
	os.Exit(dispatch(os.Args[1:]))
}

func dispatch(args []string) int {
	if len(args) == 0 {
		return runAgent(nil)
	}

	// 全局 -h / --help
	if args[0] == "-h" || args[0] == "--help" {
		if len(args) > 1 {
			return runHelp(args[1:])
		}
		printRootHelp()
		return 0
	}

	if args[0] == "help" {
		return runHelp(args[1:])
	}

	// 无子命令的 run 选项：vulnscan-agent -config agent.toml
	if isRunFlag(args[0]) {
		return runAgent(args)
	}

	cmd := normalizeCmdName(args[0])
	rest := args[1:]

	if !isKnownCommand(cmd) {
		fmt.Fprintf(os.Stderr, "未知命令: %q\n\n", args[0])
		printRootHelp()
		return 2
	}

	switch cmd {
	case "run", "start":
		return runAgent(rest)
	case "enroll":
		return runEnroll(rest)
	case "decrypt-credentials", "decrypt":
		return runDecryptCredentials(rest)
	case "config":
		return runConfigCommand(rest)
	case "version":
		fmt.Printf("%s %s\n", cliName, agentVersion())
		return 0
	default:
		return runAgent(args)
	}
}

func runHelp(args []string) int {
	if len(args) == 0 {
		printRootHelp()
		return 0
	}
	if args[0] == "config" {
		if len(args) >= 2 {
			printHelpForConfigSub(args[1])
			return 0
		}
		printConfigHelp()
		return 0
	}
	printHelpForCommand(args[0])
	return 0
}
