//! Functions resolved from the running Wireshark instead of linked: those
//! of libraries other than libwireshark, or of later release lines only.

/// The already loaded `windows_dll` on Windows; the process's global
/// symbols elsewhere, which hold Wireshark's libraries and GLib.
pub(crate) fn loaded(windows_dll: &str) -> Option<libloading::Library> {
    #[cfg(windows)]
    {
        libloading::os::windows::Library::open_already_loaded(windows_dll)
            .ok()
            .map(Into::into)
    }
    #[cfg(not(windows))]
    {
        let _ = windows_dll;
        Some(libloading::os::unix::Library::this().into())
    }
}

/// The function `name` (NUL-terminated) of `library`.
///
/// # Safety
///
/// `T` is the function's signature.
pub(crate) unsafe fn function<T: Copy>(library: &libloading::Library, name: &[u8]) -> Option<T> {
    // SAFETY: the caller's contract.
    unsafe { library.get::<T>(name) }.ok().map(|symbol| *symbol)
}
