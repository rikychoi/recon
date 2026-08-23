package service

import (
	"fmt"
	"io"
)

// progressf는 진행 상황을 지정한 Writer로 출력한다.
// Writer가 nil이면(진행 로그 비활성) 아무것도 하지 않는다.
// 진행 로그는 결과(stdout)와 분리하기 위해 보통 stderr로 출력한다.
func progressf(w io.Writer, format string, a ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format, a...)
}
