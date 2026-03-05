// +build windows
// go:build windows

package bridge

/*
#cgo LDFLAGS: -L${SRCDIR}/../../attest-rs/target/release -lattest_rs -lbcrypt -lws2_32 -luserenv -lntdll
*/
import "C"
