//! The credentials of an etcd user and the token they buy.
//!
//! etcd's `/v3/auth/authenticate` turns a user name and a password into a token that goes into
//! the `Authorization` header of every later request. A token expires (the server's TTL, or when
//! the auth store changes), and then the server answers `401`; the client asks for a new one and
//! repeats the request once. The password is read from its file once, at startup, and lives in a
//! [`Secret`]; neither it nor a token is part of any error, `Debug` output or log line.

use serde_json::json;
use tokio::sync::Mutex;

use crate::acme::Secret;

/// A user name and its password.
pub(super) struct Credentials {
    username: Box<str>,
    password: Secret,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &self.password)
            .finish()
    }
}

impl Credentials {
    pub(super) fn new(username: &str, password: Secret) -> Self {
        Self {
            username: username.into(),
            password,
        }
    }

    /// The body of the authenticate call. Never printed.
    pub(super) fn body(&self) -> Vec<u8> {
        json!({ "name": &*self.username, "password": self.password.expose() })
            .to_string()
            .into_bytes()
    }
}

/// The credentials and the current token, shared by every request of a source.
#[derive(Debug)]
pub(super) struct Auth {
    credentials: Credentials,
    token: Mutex<Option<Secret>>,
}

impl Auth {
    pub(super) fn new(credentials: Credentials) -> Self {
        Self {
            credentials,
            token: Mutex::new(None),
        }
    }

    /// A token to send. `stale` is the token that the server just refused, if any: when another
    /// request has already replaced it, the new one is returned without a second authenticate
    /// call, so a dozen watches that expire together buy one token.
    ///
    /// # Errors
    ///
    /// Whatever `authenticate` returns; the token is then unchanged.
    pub(super) async fn token<E>(
        &self,
        stale: Option<&Secret>,
        authenticate: impl AsyncFnOnce(&Credentials) -> Result<Secret, E>,
    ) -> Result<Secret, E> {
        let mut current = self.token.lock().await;
        if let Some(token) = current.as_ref()
            && Some(token) != stale
        {
            return Ok(token.clone());
        }
        let fresh = authenticate(&self.credentials).await?;
        *current = Some(fresh.clone());
        Ok(fresh)
    }
}
