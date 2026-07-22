fn main() {
    if let Err(e) = aether_engine::run_cli() {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
