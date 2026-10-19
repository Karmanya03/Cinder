//! Small mobile FFI boundary. Platform shells own document permissions;
//! cinder-core owns archive safety and compression.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;
use std::sync::Arc;

#[cfg(target_os = "android")]
use std::fs::{self, File};
#[cfg(target_os = "android")]
use std::io::{Read, Write};

use cinder_core::{compress_path, CompressOptions, ProgressEvent};

#[no_mangle]
pub extern "C" fn cinder_compress_path(input: *const c_char, output: *const c_char) -> i32 {
    let result = std::panic::catch_unwind(|| -> Result<i32, i32> {
        if input.is_null() || output.is_null() {
            return Err(-1);
        }
        let input = unsafe { CStr::from_ptr(input) }.to_str().map_err(|_| -1)?;
        let output = unsafe { CStr::from_ptr(output) }.to_str().map_err(|_| -1)?;
        let quiet: Arc<dyn Fn(&ProgressEvent) + Send + Sync> = Arc::new(|_| {});
        compress_path(Path::new(input), Path::new(output), &CompressOptions::default(), &quiet)
            .map(|_| 0)
            .map_err(|_| -2)
    });
    result.unwrap_or(Err(-3)).unwrap_or_else(|code| code)
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_karmanya03_cinder_CinderNative_compressFd(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
    input_fd: jni::sys::jint,
    output_fd: jni::sys::jint,
) -> jni::sys::jint {
    let result = std::panic::catch_unwind(|| compress_fds(input_fd, output_fd));
    result.unwrap_or(Err(-3)).unwrap_or_else(|code| code)
}

#[cfg(target_os = "android")]
fn compress_fds(input_fd: i32, output_fd: i32) -> Result<i32, i32> {
    use std::os::fd::FromRawFd;
    let input_dup = unsafe { libc::dup(input_fd) };
    let output_dup = unsafe { libc::dup(output_fd) };
    if input_dup < 0 || output_dup < 0 {
        return Err(-4);
    }
    let mut input = unsafe { File::from_raw_fd(input_dup) };
    let mut temp_input = std::env::temp_dir().join(format!("cinder-mobile-in-{}", std::process::id()));
    let mut temp_output = std::env::temp_dir().join(format!("cinder-mobile-out-{}", std::process::id()));
    let result = (|| {
        let mut staged = File::create(&temp_input).map_err(|_| -5)?;
        std::io::copy(&mut input, &mut staged).map_err(|_| -6)?;
        staged.sync_all().map_err(|_| -7)?;
        let quiet: Arc<dyn Fn(&ProgressEvent) + Send + Sync> = Arc::new(|_| {});
        compress_path(&temp_input, &temp_output, &CompressOptions::default(), &quiet)
            .map_err(|_| -8)?;
        let mut archive = File::open(&temp_output).map_err(|_| -9)?;
        let mut output = unsafe { File::from_raw_fd(output_dup) };
        std::io::copy(&mut archive, &mut output).map_err(|_| -10)?;
        output.flush().map_err(|_| -11)?;
        Ok(0)
    })();
    fs::remove_file(&temp_input).ok();
    fs::remove_file(&temp_output).ok();
    result
}
