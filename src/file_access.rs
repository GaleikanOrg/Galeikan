use std::fs::File;
use std::path::{Path, PathBuf};

pub fn open_authorized(requested: &Path, roots: &[PathBuf]) -> Result<(File, PathBuf), String> {
    open_authorized_with(requested, roots, || {})
}

fn open_authorized_with(
    requested: &Path,
    roots: &[PathBuf],
    before_open: impl FnOnce(),
) -> Result<(File, PathBuf), String> {
    let canonical = requested
        .canonicalize()
        .map_err(|error| format!("{}: {error}", requested.display()))?;
    if !is_allowed(&canonical, roots) {
        return Err(format!("file access not allowed: {}", canonical.display()));
    }
    before_open();
    let file = open_for_inspection(&canonical)
        .map_err(|error| format!("{}: {error}", canonical.display()))?;
    let opened = authorize_handle(&file, roots)?;
    if !file
        .metadata()
        .map_err(|error| format!("{}: {error}", opened.display()))?
        .is_file()
    {
        return Err(format!("file is not a regular file: {}", opened.display()));
    }
    Ok((file, opened))
}

#[cfg(target_os = "linux")]
fn open_for_inspection(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(target_os = "linux"))]
fn open_for_inspection(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

fn authorize_handle(file: &File, roots: &[PathBuf]) -> Result<PathBuf, String> {
    let opened = opened_path(file)?;
    if !is_allowed(&opened, roots) {
        return Err(format!("file access not allowed: {}", opened.display()));
    }
    Ok(opened)
}

fn is_allowed(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| path.starts_with(root))
}

#[cfg(target_os = "linux")]
fn opened_path(file: &File) -> Result<PathBuf, String> {
    use std::os::fd::AsRawFd;

    let link = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    std::fs::read_link(&link).map_err(|error| format!("cannot verify opened file path: {error}"))
}

#[cfg(windows)]
fn opened_path(file: &File) -> Result<PathBuf, String> {
    use std::ffi::{c_void, OsString};
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFinalPathNameByHandleW(
            handle: *mut c_void,
            path: *mut u16,
            capacity: u32,
            flags: u32,
        ) -> u32;
    }

    let mut buffer = vec![0_u16; 32768];
    // SAFETY: the file handle is live and the output buffer is writable.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(format!(
            "cannot verify opened file path: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn opened_path(_file: &File) -> Result<PathBuf, String> {
    Err("opened-file path verification is available only on Windows and Linux".into())
}

#[cfg(test)]
mod tests {
    use super::{authorize_handle, open_authorized};
    use std::fs;

    #[test]
    fn opened_file_must_remain_inside_granted_root() {
        let root =
            std::env::temp_dir().join(format!("galeikan-file-access-{}", std::process::id()));
        let allowed = root.join("allowed");
        let denied = root.join("denied");
        fs::create_dir_all(&allowed).unwrap();
        fs::create_dir_all(&denied).unwrap();
        let good = allowed.join("good.bin");
        let bad = denied.join("bad.bin");
        fs::write(&good, b"good").unwrap();
        fs::write(&bad, b"bad").unwrap();
        let grant = allowed.canonicalize().unwrap();
        let (_, opened) = open_authorized(&good, std::slice::from_ref(&grant)).unwrap();
        assert!(opened.starts_with(&grant));
        assert!(open_authorized(&bad, std::slice::from_ref(&grant))
            .unwrap_err()
            .contains("not allowed"));
        let foreign_handle = fs::File::open(&bad).unwrap();
        assert!(authorize_handle(&foreign_handle, &[grant])
            .unwrap_err()
            .contains("not allowed"));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn swapped_symlink_is_denied_before_reading() {
        use super::open_authorized_with;
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("galeikan-file-race-{}", std::process::id()));
        let allowed = root.join("allowed");
        let denied = root.join("denied");
        fs::create_dir_all(&allowed).unwrap();
        fs::create_dir_all(&denied).unwrap();
        let victim = allowed.join("victim.bin");
        let foreign = denied.join("foreign.bin");
        fs::write(&victim, b"allowed").unwrap();
        fs::write(&foreign, b"foreign").unwrap();
        let grant = allowed.canonicalize().unwrap();
        let error = open_authorized_with(&victim, &[grant], || {
            fs::remove_file(&victim).unwrap();
            symlink(&foreign, &victim).unwrap();
        })
        .unwrap_err();
        assert!(error.contains("file access not allowed"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }
}
