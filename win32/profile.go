// +build windows

package win32

import (
	"syscall"
	"unsafe"
)

var (
	procLoadUserProfileW  = userenvDLL.NewProc("LoadUserProfileW")
	procUnloadUserProfile = userenvDLL.NewProc("UnloadUserProfile")
)

// flags for the ProfileInfo struct
const (
	// Prevents the display of profile error messages.
	PI_NOUI = 1
)

// see https://docs.microsoft.com/en-us/windows/win32/api/profinfo/ns-profinfo-profileinfow
type ProfileInfo struct {
	Size        uint32
	Flags       uint32
	UserName    *uint16
	ProfilePath *uint16
	Defaultpath *uint16
	ServerName  *uint16
	PolicyPath  *uint16
	Profile     syscall.Handle
}

func LoadUserProfile(token *Token, profileInfo *ProfileInfo) error {
	r1, _, e1 := syscall.Syscall(
		procLoadUserProfileW.Addr(),
		2,
		uintptr(token.hToken),
		uintptr(unsafe.Pointer(profileInfo)),
		0)
	if r1 == 0 {
		if e1 != 0 {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func UnloadUserProfile(token *Token, profile syscall.Handle) error {
	r1, _, e1 := syscall.Syscall(
		procUnloadUserProfile.Addr(),
		2,
		uintptr(token.hToken),
		uintptr(profile),
		0)
	if r1 == 0 {
		if e1 != 0 {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}
