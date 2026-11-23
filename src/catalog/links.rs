//! Where each API can be reached by path, for the successor `Link` of a deprecated one.

use std::collections::HashMap;

use serde_json::Value;

use crate::router::CompiledRouter;
use podgate_model::Snapshot;

/// The path of every API entry's first router that matches one, by `tenant/id/version`.
///
/// An `id` and a `version` never hold `/` (the compiler refuses it), so the key is unambiguous
/// whatever the tenant id holds.
#[derive(Debug, Default)]
pub struct Links {
    paths: HashMap<String, Box<str>>,
}

fn key(tenant: &str, id: &str, version: &str) -> String {
    format!("{tenant}/{id}/{version}")
}

/// The literal path a matcher tree asks for: a `path` or `path_prefix` leaf, or the first of an
/// `all` that has one. An `any` or a `not` has no single path, and a regexp has no literal.
fn link_path(matcher: &Value) -> Option<&str> {
    let mut leaf = matcher.as_object()?.iter();
    let (name, argument) = leaf.next()?;
    if leaf.next().is_some() {
        return None;
    }
    match name.as_str() {
        "path" | "path_prefix" => argument.as_str(),
        "all" => argument.as_array()?.iter().find_map(link_path),
        _ => None,
    }
}

impl Links {
    /// Reads the paths from the compiled `routers` of each app of `snapshot` (same order).
    pub(crate) fn build(snapshot: &Snapshot, routers: &[Vec<CompiledRouter>]) -> Self {
        let mut paths = HashMap::new();
        for (app, compiled) in snapshot.apps.iter().zip(routers) {
            for api in &app.apis {
                let path = api
                    .routers
                    .iter()
                    .filter_map(|name| app.routers.iter().position(|router| router.name == *name))
                    .filter_map(|at| compiled.get(at))
                    .find_map(|router| link_path(router.matcher_json()));
                if let Some(path) = path {
                    paths.insert(key(&app.tenant, &api.id, &api.version), path.into());
                }
            }
        }
        Self { paths }
    }

    /// The path of the API `id` at `version` of `tenant`, when one of its routers has one.
    #[must_use]
    pub fn path(&self, tenant: &str, id: &str, version: &str) -> Option<&str> {
        self.paths
            .get(&key(tenant, id, version))
            .map(|path| &**path)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[test]
    fn lifecycle_link_path_reads_all_and_path_leaves() {
        assert_eq!(link_path(&json!({"path": "/v2/pets"})), Some("/v2/pets"));
        assert_eq!(link_path(&json!({"path_prefix": "/v2"})), Some("/v2"));
        assert_eq!(
            link_path(&json!({"all": [{"host": "a.test"}, {"path_prefix": "/v2"}]})),
            Some("/v2")
        );
        assert_eq!(link_path(&json!({"host": "a.test"})), None);
        assert_eq!(link_path(&json!({"path_regexp": "^/v2"})), None);
        assert_eq!(
            link_path(&json!({"any": [{"path": "/a"}, {"path": "/b"}]})),
            None
        );
        assert_eq!(link_path(&json!({"not": {"path": "/a"}})), None);
    }
}
