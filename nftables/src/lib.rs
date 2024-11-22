use std::{
    ffi::{CStr, CString},
    ptr::NonNull,
};

use nftables_sys as nft;

pub struct Context {
    ptr: NonNull<nft::nft_ctx>,
}

impl Context {
    pub fn new() -> Option<Context> {
        let raw = unsafe { nft::nft_ctx_new(nftables_sys::NFT_CTX_DEFAULT) };
        let mut context = NonNull::new(raw).map(|ptr| Context { ptr });

        if let Some(context) = &mut context {
            unsafe {
                let out = nft::nft_ctx_buffer_output(context.ptr.as_ptr());
                let error = nft::nft_ctx_buffer_error(context.ptr.as_ptr());

                if (out, error) != (0, 0) {
                    panic!(); // TODO
                }
            }
        }

        context
    }

    pub fn run_command(&mut self, cmd: &str, dry: bool) -> Result<String, String> {
        let buffer = CString::new(cmd).map_err(|_| "Command contained a null byte".to_string())?;
        let status = unsafe {
            nft::nft_ctx_set_dry_run(self.ptr.as_ptr(), dry);
            nft::nft_ctx_input_set_flags(self.ptr.as_ptr(), nft::NFT_CTX_INPUT_JSON);
            nft::nft_run_cmd_from_buffer(self.ptr.as_ptr(), buffer.as_ptr())
        };

        match status {
            0 => Ok(self.get_output_buffer().unwrap_or("".into())),
            _ => Err(self.get_error_buffer().unwrap_or("".into())),
        }
    }

    fn get_output_buffer(&mut self) -> Option<String> {
        let c_str = unsafe {
            let buf = nft::nft_ctx_get_output_buffer(self.ptr.as_ptr());
            if buf.is_null() {
                return None;
            }
            CStr::from_ptr(buf)
        };

        Some(c_str.to_string_lossy().to_string())
    }

    fn get_error_buffer(&mut self) -> Option<String> {
        let c_str = unsafe {
            let buf = nft::nft_ctx_get_error_buffer(self.ptr.as_ptr());
            if buf.is_null() {
                return None;
            }
            CStr::from_ptr(buf)
        };

        Some(c_str.to_string_lossy().to_string())
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            nft::nft_ctx_free(self.ptr.as_ptr());
        }
    }
}
