//go:build fcae_urnetwork && (!linux || android)

package main

func urBind(fd uintptr, name string) error { return nil }
