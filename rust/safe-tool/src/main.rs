fn main() {
    let worker = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(safe_tool::cli::main);
    let code = match worker {
        Ok(handle) => handle.join().unwrap_or(1),
        Err(_) => 1,
    };
    std::process::exit(code);
}
