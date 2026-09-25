use anyhow::Result;
use clap::Parser;
use mock_registry::{Fixtures, RunningRegistry};
use pprev_types::Layout;

/// Local HTTPS title registry. Writes the generated CA certificate so that provers can trust it.
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "policies/layouts/title-v1.json")]
    layout: String,
    #[arg(long, default_value = "mock-registry/fixtures/records.json")]
    fixtures: String,
    #[arg(long, default_value = "127.0.0.1:4443")]
    bind: String,
    /// Where to write the CA certificate (DER).
    #[arg(long, default_value = "target/registry-ca.der")]
    ca_out: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let running = RunningRegistry::start(
        Layout::load(&args.layout)?,
        Fixtures::load(&args.fixtures)?,
        &args.bind,
    )
    .await?;
    std::fs::write(&args.ca_out, &running.certs.ca_der)?;
    println!(
        "registry listening on {} (CA written to {})",
        running.addr, args.ca_out
    );
    tokio::signal::ctrl_c().await?;
    Ok(())
}
