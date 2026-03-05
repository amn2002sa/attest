// +build release,!windows,cgo
//go:build release && !windows && cgo

package bridge

/*
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/../../attest-rs/target/release -L${SRCDIR}/../../attest-rs/target/release -lattest_rs -lssl -lcrypto -lm -ldl -lpthread
*/
import "C"
