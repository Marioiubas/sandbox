//! The daemon drops the `PATH` and working directory it inherited from the
//! shell that started it (credential review, 2026-10-06): that `PATH` may
//! hold a directory a sandbox can write. Its own test binary: it changes
//! this process's environment.

#[test]
fn the_inherited_path_and_working_directory_are_dropped() {
    let d = tempfile::tempdir().unwrap();
    std::env::set_current_dir(d.path()).unwrap();
    brokerd::harden::environment().unwrap();
    assert_eq!(std::env::var("PATH").unwrap(), brokerd::harden::SAFE_PATH);
    assert_eq!(std::env::current_dir().unwrap(), std::path::Path::new("/"));
}
