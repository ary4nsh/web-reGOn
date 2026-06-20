//go:build !windows

package inputvalidation

import "syscall"

func procHideWindow() *syscall.SysProcAttr {
	return nil
}
