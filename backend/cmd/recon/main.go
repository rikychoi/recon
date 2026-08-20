// Command recon은 웹사이트 취약점 점검 CLI의 진입점이다.
package main

import (
	"os"

	"github.com/rikychoi/recon/internal/handler"
)

// main은 CLI 인자를 handler로 전달하고 반환된 종료 코드로 프로세스를 종료한다.
func main() {
	os.Exit(handler.Run(os.Args[1:]))
}
