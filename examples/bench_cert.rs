//! Writes the self-signed certificate every proxy serves in `scripts/bench-proxies.sh`.
//!
//! `bench_cert <dir> <host>...` writes `<dir>/cert.pem` and `<dir>/key.pem` (ECDSA P-256) valid
//! for the given host names, so all three proxies present the same key and certificate.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(dir) = args.next().map(PathBuf::from) else {
        eprintln!("usage: bench_cert <dir> <host>...");
        std::process::exit(2);
    };
    let hosts: Vec<String> = args.collect();
    let certified = rcgen::generate_simple_self_signed(hosts)?;
    std::fs::write(dir.join("cert.pem"), certified.cert.pem())?;
    std::fs::write(dir.join("key.pem"), certified.signing_key.serialize_pem())?;
    Ok(())
}
