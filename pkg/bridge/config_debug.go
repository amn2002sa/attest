// +build !release,!windows,cgo
//go:build !release && !windows && cgo

package bridge

/*
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/../../attest-rs/target/debug -L${SRCDIR}/../../attest-rs/target/debug -lattest_rs -lssl -lcrypto -lm -ldl -lpthread
*/
import "C"
