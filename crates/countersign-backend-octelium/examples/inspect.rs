//! Read-only check against a live cluster, using the current octeliumctl login:
//!
//!     cargo run -p countersign-backend-octelium --example inspect -- <domain> [session...]
//!
//! Lists pending sessions and prints the facts countersign would see for the
//! given sessions. Never changes anything.

use countersign_backend_octelium::{KIND_SESSION, OcteliumBackend, OcteliumConfig};
use countersign_core::{AccessBackend, SubjectRef};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let domain = args.next().ok_or("usage: inspect <domain> [session...]")?;
    let config: OcteliumConfig = toml::from_str(&format!("domain = {domain:?}"))?;
    let backend = OcteliumBackend::new("octelium".into(), config)?;

    let pending = backend.discover_pending().await?;
    println!("pending sessions: {}", pending.len());
    for p in &pending {
        println!("{}", serde_json::to_string_pretty(p)?);
    }
    for id in args {
        let subject = SubjectRef { backend: "octelium".into(), kind: KIND_SESSION.into(), id };
        println!("{} -> {}", subject.id, serde_json::to_string_pretty(&backend.verify(&subject).await?)?);
    }
    Ok(())
}
