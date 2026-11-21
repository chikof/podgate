//! The CA directory: the intermediate, the root certificate and the leaves.
//!
//! ```text
//! <dir>/                       mode 0700, the ACME broker's state directory layout
//!   intermediate.key.pem       the online CA key, the only CA key the provider holds
//!   intermediate.cert.pem      the intermediate certificate, signed by the root
//!   root.cert.pem              the root certificate (public; the root KEY is never here)
//!   index.json                 the leaf index, the commit point of every leaf
//!   certs/<id>.cert.pem        a leaf chain, leaf first (leaf, then the intermediate)
//!   certs/<id>.key.pem         its private key
//! ```
//!
//! The directory, the atomic writes, the permission checks and the leaf index are the ACME
//! broker's [`Store`]; this file adds the three CA files. `intermediate.cert.pem` is
//! the commit point of `ca init`: the files before it are written first, so a directory without
//! it is not initialized and `ca init` may be run again.

use std::path::Path;

use super::{CaError, Secret};
use crate::acme::store::{Store, StoreError, StoredCert};

const INTERMEDIATE_KEY: &str = "intermediate.key.pem";
const INTERMEDIATE_CERT: &str = "intermediate.cert.pem";
const ROOT_CERT: &str = "root.cert.pem";

/// A CA directory.
#[derive(Debug)]
pub struct CaStore {
    store: Store,
}

/// What `ca init` keeps.
pub struct Chain<'a> {
    /// The root certificate.
    pub root_cert: &'a str,
    /// The intermediate's private key.
    pub intermediate_key: &'a Secret,
    /// The intermediate certificate.
    pub intermediate_cert: &'a str,
}

impl CaStore {
    /// Opens `dir` for writing, creating it with mode `0700` when it is missing.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the directory is not private or cannot be made.
    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        Store::create(dir).map(|store| Self { store })
    }

    /// Opens an existing directory for reading; `None` when it does not exist.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when it exists but is not private or its index is unreadable.
    pub fn open_existing(dir: &Path) -> Result<Option<Self>, StoreError> {
        Ok(Store::open_existing(dir)?.map(|store| Self { store }))
    }

    /// The directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        self.store.dir()
    }

    /// Whether `ca init` finished here.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the certificate file cannot be read.
    pub fn is_initialized(&self) -> Result<bool, StoreError> {
        Ok(self.store.read_text(INTERMEDIATE_CERT)?.is_some())
    }

    /// Writes the chain: key and root certificate first, the intermediate certificate last.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when a write fails.
    pub fn save_chain(&self, chain: &Chain<'_>) -> Result<(), StoreError> {
        self.store
            .write_text(INTERMEDIATE_KEY, chain.intermediate_key.expose())?;
        self.store.write_text(ROOT_CERT, chain.root_cert)?;
        self.store
            .write_text(INTERMEDIATE_CERT, chain.intermediate_cert)
    }

    /// Replaces the intermediate (a rotation): key first, certificate last. A crash between the two
    /// leaves a key that does not match the certificate, which [`super::Ca::open`] refuses.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when a write fails.
    pub fn replace_intermediate(&self, key: &Secret, cert: &str) -> Result<(), StoreError> {
        self.store.write_text(INTERMEDIATE_KEY, key.expose())?;
        self.store.write_text(INTERMEDIATE_CERT, cert)
    }

    /// The root certificate, PEM.
    ///
    /// # Errors
    ///
    /// [`CaError::NotInitialized`] when there is none.
    pub fn root_cert(&self) -> Result<String, CaError> {
        self.required(ROOT_CERT)
    }

    /// The intermediate certificate, PEM.
    ///
    /// # Errors
    ///
    /// [`CaError::NotInitialized`] when there is none.
    pub fn intermediate_cert(&self) -> Result<String, CaError> {
        self.required(INTERMEDIATE_CERT)
    }

    /// The intermediate key.
    ///
    /// # Errors
    ///
    /// [`CaError::NotInitialized`] when there is none, [`CaError::Store`] when the file is not
    /// private.
    pub fn intermediate_key(&self) -> Result<Secret, CaError> {
        self.required(INTERMEDIATE_KEY).map(Secret::new)
    }

    fn required(&self, name: &str) -> Result<String, CaError> {
        self.store
            .read_text(name)?
            .ok_or_else(|| CaError::NotInitialized(self.dir().display().to_string().into()))
    }

    /// Every stored leaf.
    ///
    /// # Errors
    ///
    /// [`StoreError`] naming the file.
    pub fn leaves(&self) -> Result<Vec<StoredCert>, StoreError> {
        self.store.certs()
    }

    /// Stores a leaf, replacing the leaves whose hosts it covers; the index is written last.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when a write fails; the index is as it was then.
    pub fn put_leaf(
        &mut self,
        hosts: &[Box<str>],
        chain_pem: &str,
        key: &Secret,
        now: u64,
    ) -> Result<StoredCert, StoreError> {
        self.store.put_cert(hosts, chain_pem, key, now)
    }

    /// Notes that an app claimed the hosts of each leaf in `ids` at `now`.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the index cannot be written.
    pub fn touch(&mut self, ids: &[u64], now: u64) -> Result<(), StoreError> {
        self.store.touch_claimed(ids, now)
    }

    /// Drops the leaves no app has claimed for `max_age` seconds.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the index cannot be written.
    pub fn prune(&mut self, now: u64, max_age: u64) -> Result<Vec<Vec<Box<str>>>, StoreError> {
        self.store.prune(now, max_age)
    }

    /// Removes files the index does not name.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the directory cannot be listed.
    pub fn clean_orphans(&self) -> Result<(), StoreError> {
        self.store.clean_orphans()
    }
}
