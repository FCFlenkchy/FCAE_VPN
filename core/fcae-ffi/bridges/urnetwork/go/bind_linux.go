//go:build fcae_urnetwork && linux && !android

package main

import "golang.org/x/sys/unix"

func urBind(fd uintptr, name string) error {
	return unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
}
