//! The `convert-traefik` command: Traefik files in, a partial podgate snapshot out.

use std::io::Write;
use std::path::Path;

use serde_json::json;

use super::convert_file;

const USAGE: &str = "usage: podgate-provider convert-traefik [--lenient] <file>...

Converts Traefik dynamic configuration files (YAML or TOML) to the file source's format.
The snapshot JSON goes to stdout, the report of everything podgate cannot express to stderr.
Exit status: 0 when everything converted (or with --lenient), 1 when something was rejected,
2 when a file cannot be read or the arguments are wrong.";

/// Exit status of a run that converted everything, or was `--lenient`.
pub const EXIT_OK: u8 = 0;
/// Exit status of a run that rejected something.
pub const EXIT_REJECTED: u8 = 1;
/// Exit status of a run that could not read a file, or got wrong arguments.
pub const EXIT_FAILED: u8 = 2;

/// Runs `convert-traefik` with the arguments after its name, writing the snapshot to `out` and
/// the report to `err`. Returns the exit status.
pub fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let mut lenient = false;
    let mut files = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--lenient" => lenient = true,
            flag if flag.starts_with("--") => {
                let _ = writeln!(err, "unknown option {flag}\n{USAGE}");
                return EXIT_FAILED;
            }
            file => files.push(file),
        }
    }
    if files.is_empty() {
        let _ = writeln!(err, "{USAGE}");
        return EXIT_FAILED;
    }
    let mut apps = Vec::new();
    let mut certificates = Vec::new();
    let mut rejected = 0_usize;
    for file in files {
        let converted = match convert_file(Path::new(file)) {
            Ok(converted) => converted,
            Err(why) => {
                let _ = writeln!(err, "{why}");
                return EXIT_FAILED;
            }
        };
        for problem in &converted.problems {
            let _ = writeln!(err, "{file}: {problem}");
        }
        rejected += converted.problems.len();
        apps.push(converted.app);
        certificates.extend(converted.certificates);
    }
    let ids: Vec<&str> = apps.iter().filter_map(|app| app["id"].as_str()).collect();
    if let Some(duplicate) = ids
        .iter()
        .enumerate()
        .find_map(|(at, id)| ids[..at].contains(id).then_some(id))
    {
        let _ = writeln!(
            err,
            "two files have the stem {duplicate:?}, and the stem is the id of the app; rename one"
        );
        return EXIT_FAILED;
    }
    let snapshot = json!({ "apps": apps, "certificates": certificates });
    let written = serde_json::to_writer_pretty(&mut *out, &snapshot)
        .map_err(std::io::Error::from)
        .and_then(|()| writeln!(out));
    if let Err(why) = written {
        let _ = writeln!(err, "cannot write the snapshot: {why}");
        return EXIT_FAILED;
    }
    if rejected == 0 {
        return EXIT_OK;
    }
    let _ = writeln!(
        err,
        "{rejected} problem(s): what is named above was left out"
    );
    if lenient { EXIT_OK } else { EXIT_REJECTED }
}
