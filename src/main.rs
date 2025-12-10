use kevi::cli::runner;

#[tokio::main]
async fn main() {
    if let Err(e) = runner::run().await {
        eprintln!("❌ Error: {e}");
        std::process::exit(1);
    }
}
