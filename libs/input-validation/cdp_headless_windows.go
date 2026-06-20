//go:build windows

package inputvalidation

import "syscall"

func procHideWindow() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true}
}
