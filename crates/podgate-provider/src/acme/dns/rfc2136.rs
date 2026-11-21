//! RFC 2136 dynamic updates, signed with TSIG (RFC 8945), over TCP.
//!
//! The client is written here on `hickory-proto`, which builds and signs the messages. One update
//! adds one TXT value to the RRset at the name, or removes exactly that value; other values of the
//! RRset stay (an apex and its wildcard share one name). The answer is accepted only when its
//! TSIG verifies, so a forged "NOERROR" cannot make the broker report a record that was never
//! written. The key never leaves the [`TSigner`], whose `Debug` shows no key bytes.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_proto::op::update_message::{append, delete_by_rdata};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::TSigner;
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{Name, RData, RecordSet, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::Failure;

/// Seconds a server may be off by when it checks the signature time.
pub(super) const FUDGE: u16 = 300;
/// The TTL of a challenge record: short, so a stale one expires quickly.
pub(super) const TTL: u32 = 60;
/// Largest answer read. An update answer is a header and a TSIG record.
const MAX_ANSWER: usize = 4096;

/// The server of one zone and the key to sign with.
pub(super) struct Rfc2136 {
    server: Box<str>,
    signer: TSigner,
    wait: Duration,
}

impl std::fmt::Debug for Rfc2136 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rfc2136")
            .field("server", &self.server)
            .field("key", &self.signer.signer_name().to_ascii())
            .finish_non_exhaustive()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl Rfc2136 {
    pub(super) fn new(server: Box<str>, signer: TSigner, wait: Duration) -> Self {
        Self {
            server,
            signer,
            wait,
        }
    }

    /// Adds (`add`) or removes the TXT `value` at `name` in `zone`.
    pub(super) async fn update(
        &self,
        zone: &Name,
        name: &Name,
        value: &str,
        add: bool,
    ) -> Result<(), Failure> {
        let mut records = RecordSet::with_ttl(name.clone(), RecordType::TXT, TTL);
        records.add_rdata(RData::TXT(TXT::new(vec![value.to_owned()])));
        let mut message = if add {
            append(records, zone.clone(), false, false)
        } else {
            delete_by_rdata(records, zone.clone(), false)
        };
        let mut verifier = message
            .finalize(&self.signer, now())
            .map_err(|err| Failure::Permanent(format!("cannot sign the update ({err})")))?
            .ok_or_else(|| Failure::Permanent("the update has no signature".into()))?;
        let bytes = message
            .to_vec()
            .map_err(|err| Failure::Permanent(format!("cannot encode the update ({err})")))?;
        let answer = timeout(self.wait, self.exchange(&bytes))
            .await
            .map_err(|_| Failure::Retry(format!("{} did not answer in time", self.server)))??;

        // The code is read before the signature is checked, so a refusal (the server does not
        // know the key, or the key is wrong) says so instead of "bad signature".
        let code = Message::from_vec(&answer)
            .map_err(|err| Failure::Retry(format!("unreadable answer ({err})")))?
            .metadata
            .response_code;
        match code {
            ResponseCode::NoError => {}
            ResponseCode::ServFail => {
                return Err(Failure::Retry("the server answered SERVFAIL".into()));
            }
            other => {
                return Err(Failure::Permanent(format!(
                    "the server refused the update: {other} (check the zone, the key name and the key)"
                )));
            }
        }
        verifier
            .verify(&answer)
            .map_err(|_| Failure::Permanent("the answer is not signed with the TSIG key".into()))?;
        Ok(())
    }

    async fn exchange(&self, update: &[u8]) -> Result<Vec<u8>, Failure> {
        let retry = |what: &str, err: std::io::Error| Failure::Retry(format!("{what} ({err})"));
        let mut stream = TcpStream::connect(&*self.server)
            .await
            .map_err(|err| retry("cannot connect to the server", err))?;
        let length = u16::try_from(update.len())
            .map_err(|_| Failure::Permanent("the update is too long".into()))?;
        let mut frame = length.to_be_bytes().to_vec();
        frame.extend_from_slice(update);
        stream
            .write_all(&frame)
            .await
            .map_err(|err| retry("cannot send the update", err))?;
        let mut prefix = [0u8; 2];
        stream
            .read_exact(&mut prefix)
            .await
            .map_err(|err| retry("no answer", err))?;
        let size = usize::from(u16::from_be_bytes(prefix));
        if size > MAX_ANSWER {
            return Err(Failure::Retry("the answer is too long".into()));
        }
        let mut answer = vec![0u8; size];
        stream
            .read_exact(&mut answer)
            .await
            .map_err(|err| retry("short answer", err))?;
        Ok(answer)
    }
}
