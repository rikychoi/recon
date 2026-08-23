//go:build !unix

package service

import "syscall"

// detachedProcAttr는 비유닉스 플랫폼에서는 별도 분리 속성을 사용하지 않는다.
func detachedProcAttr() *syscall.SysProcAttr {
	return nil
}
