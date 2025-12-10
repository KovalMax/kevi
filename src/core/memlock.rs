use anyhow::Result;

/// Best‑effort memory locking helpers for derived keys.
///
/// On Unix when the `memlock` feature is enabled, these functions attempt to
/// mlock/munlock the given slice for the duration of a sensitive operation.
/// On other platforms or when the feature is disabled, they are no‑ops.
#[inline]
pub fn lock_slice(_data: &mut [u8]) -> Result<()> {
    #[cfg(all(target_family = "unix", feature = "memlock"))]
    {
        // Safety: libc::mlock reads the pointer and length; it does not take
        // ownership. The kernel rounds to page boundaries.
        let ptr = _data.as_ptr() as *const core::ffi::c_void;
        let len = _data.len();
        if len == 0 {
            return Ok(());
        }
        let rc = unsafe { libc::mlock(ptr, len) };
        // Best‑effort: ignore failures, continue operation
        let _ = rc; // keep silent; ops proceed regardless
    }
    Ok(())
}

#[inline]
pub fn unlock_slice(_data: &mut [u8]) -> Result<()> {
    #[cfg(all(target_family = "unix", feature = "memlock"))]
    {
        let ptr = _data.as_ptr() as *const core::ffi::c_void;
        let len = _data.len();
        if len == 0 {
            return Ok(());
        }
        let rc = unsafe { libc::munlock(ptr, len) };
        let _ = rc; // best‑effort; ignore errors
    }
    Ok(())
}
