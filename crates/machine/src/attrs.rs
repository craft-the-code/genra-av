//! File attributes Windows uses to hide items (Hidden, System). USB worms set both on the real
//! folders of a stick and leave shortcuts in their place; Explorer then shows only the shortcuts.
//! Elsewhere there are no such attributes: reads return 0 and writes are refused.

use anyhow::Result;
use std::path::Path;

pub const HIDDEN: u32 = 0x2;
pub const SYSTEM: u32 = 0x4;

#[cfg(windows)]
fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// The item's attribute bits.
#[cfg(windows)]
pub fn get(path: &Path) -> Result<u32> {
    use windows_sys::Win32::Storage::FileSystem::{GetFileAttributesW, INVALID_FILE_ATTRIBUTES};
    let a = unsafe { GetFileAttributesW(wide(path).as_ptr()) };
    if a == INVALID_FILE_ATTRIBUTES {
        anyhow::bail!("cannot read the attributes of {}: {}", path.display(), std::io::Error::last_os_error());
    }
    Ok(a)
}

/// Sets the item's attribute bits (only the ones SetFileAttributes accepts are kept).
#[cfg(windows)]
pub fn set(path: &Path, attrs: u32) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::SetFileAttributesW;
    // Only the bits SetFileAttributes may change (read-only, hidden, system, archive, not
    // content indexed, offline, temporary): directory and reparse bits are not ours to pass.
    let settable = attrs & 0x0000_3127;
    if unsafe { SetFileAttributesW(wide(path).as_ptr(), settable) } == 0 {
        anyhow::bail!("cannot change the attributes of {}: {}", path.display(), std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn get(_path: &Path) -> Result<u32> {
    Ok(0)
}

#[cfg(not(windows))]
pub fn set(path: &Path, _attrs: u32) -> Result<()> {
    anyhow::bail!("{}: file attributes are a Windows feature", path.display())
}
