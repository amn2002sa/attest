#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::id::AttestAgent;
use std::ffi::CString;
use std::os::raw::c_char;

use crate::tpm::create_identity_provider;
use crate::traits::HardwareIdentity;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static STRICT_HARDWARE: AtomicBool = AtomicBool::new(false);

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create Tokio runtime")
    })
}

#[no_mangle]
pub extern "C" fn attest_agent_new() -> *mut AttestAgent {
    let agent = AttestAgent::new();
    Box::into_raw(Box::new(agent))
}

#[no_mangle]
pub extern "C" fn attest_agent_free(ptr: *mut AttestAgent) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn attest_agent_get_id(ptr: *mut AttestAgent) -> *mut c_char {
    let agent = unsafe {
        assert!(!ptr.is_null());
        &*ptr
    };
    let c_str = CString::new(agent.id.clone()).unwrap();
    c_str.into_raw()
}

#[no_mangle]
pub extern "C" fn attest_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn attest_set_strict_hardware(strict: bool) {
    STRICT_HARDWARE.store(strict, Ordering::SeqCst);
}

#[no_mangle]
pub extern "C" fn attest_seal(data: *const u8, data_len: usize, out_len: *mut usize) -> *mut u8 {
    let result = std::panic::catch_unwind(|| {
        let rt = get_runtime();
        let strict = STRICT_HARDWARE.load(Ordering::SeqCst);
        let tpm: Box<dyn HardwareIdentity> = create_identity_provider(!strict);
        let input = unsafe { std::slice::from_raw_parts(data, data_len) };

        match rt.block_on(tpm.seal("default", input)) {
            Ok(sealed) => unsafe {
                *out_len = sealed.len();
                let mut buf = sealed.into_boxed_slice();
                let ptr = buf.as_mut_ptr();
                std::mem::forget(buf);
                ptr
            },
            Err(e) => {
                eprintln!("[FFI] seal error: {}", e);
                std::ptr::null_mut()
            }
        }
    });

    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            eprintln!("[FFI] attest_seal PANICKED");
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn attest_unseal(blob: *const u8, blob_len: usize, out_len: *mut usize) -> *mut u8 {
    let result = std::panic::catch_unwind(|| {
        let rt = get_runtime();
        let strict = STRICT_HARDWARE.load(Ordering::SeqCst);
        let tpm: Box<dyn HardwareIdentity> = create_identity_provider(!strict);
        let input = unsafe { std::slice::from_raw_parts(blob, blob_len) };

        match rt.block_on(tpm.unseal(input)) {
            Ok(unsealed) => unsafe {
                *out_len = unsealed.len();
                let mut buf = unsealed.into_boxed_slice();
                let ptr = buf.as_mut_ptr();
                std::mem::forget(buf);
                ptr
            },
            Err(e) => {
                eprintln!("[FFI] unseal error: {}", e);
                std::ptr::null_mut()
            }
        }
    });

    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            eprintln!("[FFI] attest_unseal PANICKED");
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn attest_free_buffer(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len));
        }
    }
}
