// +build !cgo
//go:build !cgo

package bridge

func IsCgoEnabled() bool {
	return false
}
