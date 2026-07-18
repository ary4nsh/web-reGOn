//go:build windows

package clientside

import "syscall"

func procHideWindow() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true}
}
