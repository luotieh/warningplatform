package main

import (
	"os"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "enroll":
			os.Exit(runEnroll(os.Args[2:]))
		case "decrypt-credentials":
			os.Exit(runDecryptCredentials(os.Args[2:]))
		case "help", "-h", "--help":
			printAgentHelp()
			return
		}
	}
	runAgentMain()
}
