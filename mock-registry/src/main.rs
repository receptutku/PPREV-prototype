use anyhow::Result;
use clap::Parser;
use mock_registry::{Fixtures, PhaseLayouts, RunningRegistry};
use pprev_types::{Layout, RecordLayout};

/// Local HTTPS registry. Writes the generated CA certificate so that provers can trust it.
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "policies/layouts/title-v1.json")]
    layout: String,
    /// Layout of the eligibility source (phi_A); without it, `/income` is not served.
    #[arg(long)]
    income_layout: Option<String>,
    /// Layout of the settlement source (phi_S); without it, `/tenancy/` is not served.
    #[arg(long)]
    tenancy_layout: Option<String>,
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
    let phases = PhaseLayouts {
        income: args
            .income_layout
            .as_deref()
            .map(RecordLayout::load)
            .transpose()?,
        tenancy: args
            .tenancy_layout
            .as_deref()
            .map(RecordLayout::load)
            .transpose()?,
    };
    let running = RunningRegistry::start_with_phases(
        Layout::load(&args.layout)?,
        phases,
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
