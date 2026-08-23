//go:build unix

package service

import "syscall"

// detachedProcAttr는 자식 프로세스를 새 세션(setsid)으로 분리하는 속성을 반환한다.
// msfconsole은 stdin 리다이렉트와 무관하게 제어 터미널(/dev/tty)을 직접 열어
// raw 모드로 전환하므로, 부모 터미널이 먹통이 되는 것을 막기 위해 제어 터미널에서
// 분리한다.
func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
