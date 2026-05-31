#[tokio::main]
async fn main() {
    if let Err(e) = kevi::api::run().await {
        eprintln!("❌ {e}");
        std::process::exit(1);
    }
}
