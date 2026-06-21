#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    magic_context_dashboard_lib::webserver::serve_from_env().await
}
