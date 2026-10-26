use crate::bytes::hex_bytes;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const MAX_DOCUMENT: usize = 16 * 1024 * 1024;
pub const MAX_BLOBS: usize = 20_000;
pub const MAX_BLOB_BYTES: usize = 512 * 1024 * 1024;
const MAX_EVENTS: usize = 10_000;
const MAX_LINEAGE: usize = 65;
const MAX_ARTIFACTS: usize = 4096;

pub fn archive_dir(path: &Path) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(".blobs");
    PathBuf::from(name)
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

pub fn write_archive<'a>(
    path: &Path,
    payload: &[u8],
    blobs: impl Iterator<Item = (&'a str, &'a [u8])>,
) -> Result<(), String> {
    let blobs: Vec<_> = blobs.collect();
    if path.exists() {
        return Err(format!("case output already exists: {}", path.display()));
    }
    let archive = archive_dir(path);
    if archive.exists() {
        return Err(format!(
            "case archive already exists: {}",
            archive.display()
        ));
    }
    let mut created_files = Vec::new();
    let mut created_dir = false;
    let mut created_case = false;
    let result = (|| -> Result<(), String> {
        if !blobs.is_empty() {
            create_private_dir(&archive)
                .map_err(|e| format!("cannot create case archive {}: {e}", archive.display()))?;
            created_dir = true;
        }
        for (hash, bytes) in blobs {
            if !valid_hash(hash) {
                return Err("invalid case blob hash".into());
            }
            let blob_path = archive.join(format!("{hash}.bin"));
            let mut file = create_private_file(&blob_path)
                .map_err(|e| format!("cannot create case blob {}: {e}", blob_path.display()))?;
            created_files.push(blob_path.clone());
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|e| format!("cannot write case blob {}: {e}", blob_path.display()))?;
        }
        let mut file = create_private_file(path)
            .map_err(|e| format!("cannot create case {}: {e}", path.display()))?;
        created_case = true;
        file.write_all(payload)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("cannot write case {}: {e}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        if created_case {
            let _ = fs::remove_file(path);
        }
        for file in created_files {
            let _ = fs::remove_file(file);
        }
        if created_dir {
            let _ = fs::remove_dir(&archive);
        }
    }
    result
}

pub fn verify(path: &Path) -> Result<(usize, usize), String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| format!("cannot read case {}: {e}", path.display()))?
        .take((MAX_DOCUMENT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read case {}: {e}", path.display()))?;
    if bytes.len() > MAX_DOCUMENT {
        return Err("case document exceeds size limit".into());
    }
    let document: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid case JSON: {e}"))?;
    if document.get("format").and_then(Value::as_str) != Some("galeikan.case") {
        return Err("invalid case format".into());
    }
    let version = document.get("version").and_then(Value::as_u64);
    if !matches!(version, Some(2 | 3)) {
        return Err("case verification requires format version 2 or 3".into());
    }
    let records = document
        .get("blobs")
        .and_then(Value::as_array)
        .ok_or("case has no blob manifest")?;
    if records.len() > MAX_BLOBS {
        return Err("case has too many blobs".into());
    }
    let archive = archive_dir(path);
    if records.is_empty() && archive.exists() {
        return Err("case has an unexpected blob archive".into());
    }
    if !records.is_empty() {
        let metadata = fs::symlink_metadata(&archive)
            .map_err(|e| format!("cannot inspect case archive {}: {e}", archive.display()))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("case blob archive is not a regular directory".into());
        }
    }
    let mut blobs = BTreeMap::new();
    let mut total = 0_usize;
    for record in records {
        let hash = record
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or("case blob has no SHA-256")?;
        if !valid_hash(hash) || blobs.contains_key(hash) {
            return Err("case blob has invalid or duplicate SHA-256".into());
        }
        let size = record
            .get("size")
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or("case blob has invalid size")?;
        total = total.checked_add(size).ok_or("case blob size overflow")?;
        if total > MAX_BLOB_BYTES {
            return Err("case blobs exceed size limit".into());
        }
        let blob_path = archive.join(format!("{hash}.bin"));
        let metadata = fs::symlink_metadata(&blob_path)
            .map_err(|e| format!("cannot inspect case blob {}: {e}", blob_path.display()))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != size as u64
        {
            return Err(format!(
                "case blob has invalid type or size: {}",
                blob_path.display()
            ));
        }
        let mut data = Vec::new();
        fs::File::open(&blob_path)
            .map_err(|e| format!("cannot read case blob {}: {e}", blob_path.display()))?
            .take((size as u64) + 1)
            .read_to_end(&mut data)
            .map_err(|e| format!("cannot read case blob {}: {e}", blob_path.display()))?;
        if data.len() != size || hex_bytes(&Sha256::digest(&data)) != hash {
            return Err(format!(
                "case blob SHA-256 mismatch: {}",
                blob_path.display()
            ));
        }
        blobs.insert(hash.to_owned(), data);
    }
    if !records.is_empty() {
        let mut actual = BTreeSet::new();
        for item in fs::read_dir(&archive)
            .map_err(|e| format!("cannot inspect case archive {}: {e}", archive.display()))?
        {
            let item = item.map_err(|e| format!("cannot inspect case archive entry: {e}"))?;
            actual.insert(item.file_name());
        }
        let expected: BTreeSet<_> = blobs
            .keys()
            .map(|hash| OsString::from(format!("{hash}.bin")))
            .collect();
        if actual != expected {
            return Err("case archive contains unexpected or missing files".into());
        }
    }
    let events = document
        .get("events")
        .and_then(Value::as_array)
        .ok_or("case has no events")?;
    if events.len() > MAX_EVENTS {
        return Err("case has too many events".into());
    }
    let mut used = BTreeSet::new();
    for event in events {
        let value = event.get("value").ok_or("case event has no value")?;
        verify_value(value, &blobs, &mut used)?;
    }
    if version == Some(3) {
        verify_artifacts(&document, &blobs, &mut used)?;
    }
    if used.len() != blobs.len() {
        return Err("case manifest contains unreferenced blobs".into());
    }
    Ok((events.len(), blobs.len()))
}

fn valid_artifact_path(path: &str, kind: &str) -> bool {
    let valid_extension = match kind {
        "galeikan.source" => path.ends_with(".gak") || path.ends_with(".gaks"),
        "galeikan.bundle" => path.ends_with(".gakb"),
        "python.module" => path.ends_with(".py"),
        _ => return false,
    };
    !path.is_empty()
        && path.len() <= 4096
        && valid_extension
        && !path.contains(['\\', ':'])
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn verify_artifacts(
    document: &Value,
    blobs: &BTreeMap<String, Vec<u8>>,
    used: &mut BTreeSet<String>,
) -> Result<(), String> {
    let artifacts = document
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or("case has no artifact manifest")?;
    if artifacts.is_empty() || artifacts.len() > MAX_ARTIFACTS {
        return Err("case artifact count is invalid".into());
    }
    let args = document
        .get("arguments")
        .and_then(Value::as_array)
        .ok_or("case has no argument list")?;
    if args.len() > 1024 || args.iter().any(|arg| arg.as_str().is_none()) {
        return Err("case arguments are invalid".into());
    }
    let entry = document
        .get("entry")
        .and_then(Value::as_str)
        .ok_or("case has no entry path")?;
    if !valid_artifact_path(entry, "galeikan.source") {
        return Err("case entry path is invalid".into());
    }
    let mode = document
        .get("program_mode")
        .and_then(Value::as_str)
        .ok_or("case has no program mode")?;
    if mode != "source" && mode != "bundle" {
        return Err("case program mode is invalid".into());
    }
    let program_sha256 = document
        .get("program_sha256")
        .and_then(Value::as_str)
        .ok_or("case has no program hash")?;
    if !valid_hash(program_sha256) {
        return Err("case program hash is invalid".into());
    }
    if document.get("program_blob_sha256").and_then(Value::as_str) != Some(program_sha256) {
        return Err("case program blob hash differs from program hash".into());
    }
    let program = blobs
        .get(program_sha256)
        .ok_or("case program blob is missing")?;
    let program_document: Value =
        serde_json::from_slice(program).map_err(|_| "case program blob is invalid JSON")?;
    if program_document.get("entry").and_then(Value::as_str) != Some(entry) {
        return Err("case program blob entry differs from case entry".into());
    }
    used.insert(program_sha256.to_owned());
    let stem = entry
        .strip_suffix(".gak")
        .or_else(|| entry.strip_suffix(".gaks"))
        .ok_or("case entry path is invalid")?;
    let expected_bundle = format!("{stem}.gakb");
    let mut names = BTreeSet::new();
    let mut primary = None;
    for record in artifacts {
        let kind = record
            .get("kind")
            .and_then(Value::as_str)
            .ok_or("case artifact has no kind")?;
        let path = record
            .get("path")
            .and_then(Value::as_str)
            .ok_or("case artifact has no path")?;
        if !valid_artifact_path(path, kind) || !names.insert((kind.to_owned(), path.to_owned())) {
            return Err("case artifact has invalid or duplicate identity".into());
        }
        let hash = record
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or("case artifact has no SHA-256")?;
        let size = record
            .get("size")
            .and_then(Value::as_u64)
            .ok_or("case artifact has no size")?;
        let data = blobs.get(hash).ok_or("case artifact blob is missing")?;
        if size != data.len() as u64 {
            return Err("case artifact size differs from blob".into());
        }
        let is_primary = (mode == "source" && kind == "galeikan.source" && path == entry)
            || (mode == "bundle" && kind == "galeikan.bundle" && path == expected_bundle);
        if is_primary && primary.replace(hash).is_some() {
            return Err("case has duplicate primary program artifact".into());
        }
        used.insert(hash.to_owned());
    }
    let primary = primary.ok_or("case has no primary program artifact")?;
    if mode == "bundle" {
        let bytes = &blobs[primary];
        if bytes.len() < 48 || &bytes[..8] != b"GAKB\x0a\x00\x00\x00" {
            return Err("case bundle artifact is invalid".into());
        }
        let size = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let payload = &bytes[48..];
        if size != payload.len() as u64
            || Sha256::digest(payload).as_slice() != &bytes[16..48]
            || hex_bytes(&Sha256::digest(payload)) != program_sha256
        {
            return Err("case bundle artifact does not match program hash".into());
        }
    }
    Ok(())
}

fn verify_value(
    value: &Value,
    blobs: &BTreeMap<String, Vec<u8>>,
    used: &mut BTreeSet<String>,
) -> Result<(), String> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    match object.get("$galeikan").and_then(Value::as_str) {
        Some("Source") => verify_value_lineage(value, "lineage", "sha256", blobs, used)?,
        Some("Observation" | "Format" | "Section" | "Finding" | "Instruction" | "Disassembly") => {
            verify_value_lineage(value, "source_lineage", "sha256", blobs, used)?;
        }
        Some("Diff") => {
            verify_value_lineage(value, "left_lineage", "left_sha256", blobs, used)?;
            verify_value_lineage(value, "right_lineage", "right_sha256", blobs, used)?;
        }
        Some("Result") if object.get("ok").and_then(Value::as_bool) == Some(true) => {
            verify_value(
                object.get("value").ok_or("case Result has no value")?,
                blobs,
                used,
            )?;
        }
        Some("HttpResponse") => {
            let status = object
                .get("status")
                .and_then(Value::as_u64)
                .ok_or("case HttpResponse has no status")?;
            if !(100..=599).contains(&status) {
                return Err("case HttpResponse status is invalid".into());
            }
            let headers = object
                .get("headers")
                .and_then(Value::as_array)
                .ok_or("case HttpResponse has no headers")?;
            if headers.len() > 64
                || headers.iter().any(|entry| {
                    let Some(pair) = entry.as_array() else {
                        return true;
                    };
                    pair.len() != 2 || pair.iter().any(|part| part.as_str().is_none())
                })
            {
                return Err("case HttpResponse headers are invalid".into());
            }
            verify_value(
                object
                    .get("request")
                    .ok_or("case HttpResponse has no request")?,
                blobs,
                used,
            )?;
            verify_value(
                object.get("body").ok_or("case HttpResponse has no body")?,
                blobs,
                used,
            )?;
        }
        Some("bytes" | "Offsets" | "Regions" | "Region") => {}
        Some(_) | None => return Err("case contains an unknown Galeikan value type".into()),
    }
    Ok(())
}

fn verify_value_lineage(
    value: &Value,
    key: &str,
    hash_key: &str,
    blobs: &BTreeMap<String, Vec<u8>>,
    used: &mut BTreeSet<String>,
) -> Result<(), String> {
    let expected = value
        .get(hash_key)
        .and_then(Value::as_str)
        .ok_or("case value has no Source hash")?;
    let lineage = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or("case value has no Source lineage")?;
    let actual = verify_lineage(lineage, blobs, used)?;
    if actual != expected {
        return Err("case value Source hash differs from lineage".into());
    }
    Ok(())
}

fn verify_lineage(
    lineage: &[Value],
    blobs: &BTreeMap<String, Vec<u8>>,
    used: &mut BTreeSet<String>,
) -> Result<String, String> {
    if lineage.is_empty() || lineage.len() > MAX_LINEAGE {
        return Err("case Source lineage has invalid length".into());
    }
    let mut previous = None;
    for (index, node) in lineage.iter().enumerate() {
        let hash = node
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or("case lineage node has no SHA-256")?;
        let data = blobs
            .get(hash)
            .ok_or("case lineage references a missing blob")?;
        let size = node
            .get("size")
            .and_then(Value::as_u64)
            .ok_or("case lineage node has no size")?;
        if size != data.len() as u64 {
            return Err("case lineage node size differs from blob".into());
        }
        let operation = node
            .get("operation")
            .and_then(Value::as_str)
            .ok_or("case lineage node has no operation")?;
        if index == 0 {
            if operation != "capture" {
                return Err("case lineage does not begin with capture".into());
            }
        } else {
            let parent_hash: &str = previous.ok_or("case lineage has no parent")?;
            if node.get("parent_sha256").and_then(Value::as_str) != Some(parent_hash) {
                return Err("case lineage parent hash mismatch".into());
            }
            let parent = blobs
                .get(parent_hash)
                .ok_or("case lineage parent blob missing")?;
            let start = node
                .get("start")
                .and_then(Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
                .ok_or("case lineage has invalid start")?;
            let end = node
                .get("end")
                .and_then(Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
                .ok_or("case lineage has invalid end")?;
            if start > end || end > parent.len() {
                return Err("case lineage range is out of bounds".into());
            }
            match operation {
                "view" if data == &parent[start..end] => {}
                "view" => return Err("case view bytes differ from parent range".into()),
                "patch" => {
                    if data.len() != parent.len()
                        || data[..start] != parent[..start]
                        || data[end..] != parent[end..]
                    {
                        return Err("case patch changed bytes outside its range".into());
                    }
                    let replacement = node
                        .get("replacement_sha256")
                        .and_then(Value::as_str)
                        .ok_or("case patch has no replacement hash")?;
                    if hex_bytes(&Sha256::digest(&data[start..end])) != replacement {
                        return Err("case patch replacement hash mismatch".into());
                    }
                }
                "splice" => {
                    let inserted_size = node
                        .get("inserted_size")
                        .and_then(Value::as_u64)
                        .and_then(|n| usize::try_from(n).ok())
                        .ok_or("case splice has invalid inserted size")?;
                    let inserted_end = start
                        .checked_add(inserted_size)
                        .ok_or("case splice size overflow")?;
                    let expected_size = parent
                        .len()
                        .checked_sub(end - start)
                        .and_then(|size| size.checked_add(inserted_size))
                        .ok_or("case splice size overflow")?;
                    if (start == end && inserted_size == 0)
                        || data.len() != expected_size
                        || inserted_end > data.len()
                        || data[..start] != parent[..start]
                        || data[inserted_end..] != parent[end..]
                    {
                        return Err("case splice changed bytes outside its range".into());
                    }
                    let replacement = node
                        .get("replacement_sha256")
                        .and_then(Value::as_str)
                        .ok_or("case splice has no replacement hash")?;
                    if hex_bytes(&Sha256::digest(&data[start..inserted_end])) != replacement {
                        return Err("case splice replacement hash mismatch".into());
                    }
                }
                _ => return Err("case lineage has unknown operation".into()),
            }
        }
        used.insert(hash.to_owned());
        previous = Some(hash);
    }
    Ok(previous.unwrap().to_owned())
}
