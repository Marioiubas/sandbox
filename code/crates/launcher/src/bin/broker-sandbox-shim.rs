//! First process inside every sandbox; see `launcher::shim`.
fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    launcher::shim::main_with_args(args)
}
