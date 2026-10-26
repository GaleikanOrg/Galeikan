use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_MANIFEST: u64 = 1024 * 1024;
const MAX_PACKAGE_FILES: usize = 4096;
const MAX_PACKAGE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestV1 {
    version: u32,
    dependencies: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestV2 {
    version: u32,
    #[serde(default)]
    package: Option<PackageIdentity>,
    dependencies: BTreeMap<String, VersionedDependency>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageIdentity {
    name: String,
    version: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionedDependency {
    path: String,
    version: String,
}

enum Manifest {
    V1(ManifestV1),
    V2(ManifestV2),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lockfile {
    version: u32,
    dependencies: BTreeMap<String, LockedDependency>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockedDependency {
    path: String,
    sha256: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LockfileV2 {
    version: u32,
    roots: Vec<String>,
    dependencies: BTreeMap<String, LockedDependencyV2>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LockedDependencyV2 {
    path: String,
    version: String,
    sha256: String,
    dependencies: Vec<String>,
}

pub struct Project {
    pub root: PathBuf,
    pub packages: BTreeMap<String, PathBuf>,
}

pub fn is_source_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|part| part.to_str()),
        Some("gak" | "gaks")
    )
}

pub fn source_module_path(base: &Path, target: &str) -> Result<PathBuf, String> {
    if target.ends_with(".gak") || target.ends_with(".gaks") {
        return Ok(base.join(target));
    }
    let stem = if target.contains('/') || target.contains('\\') {
        target.to_owned()
    } else {
        target.replace('.', "/")
    };
    let lang = base.join(format!("{stem}.gak"));
    let script = base.join(format!("{stem}.gaks"));
    match (lang.is_file(), script.is_file()) {
        (true, true) => Err(format!(
            "ambiguous Galeikan module {target}: both .gak and .gaks exist"
        )),
        (false, true) => Ok(script),
        _ => Ok(lang),
    }
}

pub fn resolve(entry: &Path) -> Result<Project, String> {
    let parent = entry.parent().ok_or("entry has no parent directory")?;
    let Some(root) = parent
        .ancestors()
        .find(|dir| dir.join("galeikan.json").is_file())
    else {
        return Ok(Project {
            root: parent.to_path_buf(),
            packages: BTreeMap::new(),
        });
    };
    let root = root.to_path_buf();
    let manifest = read_manifest(&root)?;
    let has_dependencies = match &manifest {
        Manifest::V1(value) => !value.dependencies.is_empty(),
        Manifest::V2(value) => !value.dependencies.is_empty(),
    };
    if !has_dependencies {
        return Ok(Project {
            root,
            packages: BTreeMap::new(),
        });
    }
    match manifest {
        Manifest::V1(manifest) => resolve_v1(root, manifest),
        Manifest::V2(manifest) => resolve_v2(root, manifest),
    }
}

fn resolve_v1(root: PathBuf, manifest: ManifestV1) -> Result<Project, String> {
    let lock = read_lock(&root)?;
    if lock.version != 1 || lock.dependencies.len() != manifest.dependencies.len() {
        return Err(
            "galeikan.lock does not match galeikan.json; run galeikan lock <project>".into(),
        );
    }
    let mut packages = BTreeMap::new();
    for (name, relative) in manifest.dependencies {
        let locked = lock
            .dependencies
            .get(&name)
            .ok_or_else(|| format!("missing locked dependency {name}"))?;
        if locked.path != relative {
            return Err(format!(
                "dependency {name} path changed; run galeikan lock <project>"
            ));
        }
        let path = dependency_path(&root, &relative)?;
        let actual = hash_package(&path)?;
        if actual != locked.sha256 {
            return Err(format!("dependency {name} differs from galeikan.lock; run galeikan lock <project> after reviewing changes"));
        }
        packages.insert(name, path);
    }
    Ok(Project { root, packages })
}

fn resolve_v2(root: PathBuf, manifest: ManifestV2) -> Result<Project, String> {
    let (expected, packages) = build_lock_v2(&root, &manifest)?;
    let path = root.join("galeikan.lock");
    let actual: LockfileV2 =
        read_json(&path).map_err(|e| format!("{e}; run galeikan lock <project>"))?;
    if actual != expected {
        return Err("project differs from galeikan.lock: dependency graph or package contents changed; review changes, then run galeikan lock <project>".into());
    }
    Ok(Project { root, packages })
}

pub fn lock(project_dir: &Path) -> Result<PathBuf, String> {
    let root = project_dir.canonicalize().map_err(|e| {
        format!(
            "cannot read project directory {}: {e}",
            project_dir.display()
        )
    })?;
    if !root.is_dir() {
        return Err("project path must be a directory".into());
    }
    let manifest = read_manifest(&root)?;
    let contents = match manifest {
        Manifest::V1(manifest) => lock_v1(&root, manifest)?,
        Manifest::V2(manifest) => {
            let (lock, _) = build_lock_v2(&root, &manifest)?;
            encode_lock(&lock)?
        }
    };
    let output = root.join("galeikan.lock");
    fs::write(&output, contents).map_err(|e| format!("cannot write {}: {e}", output.display()))?;
    Ok(output)
}

fn lock_v1(root: &Path, manifest: ManifestV1) -> Result<Vec<u8>, String> {
    let mut dependencies = BTreeMap::new();
    for (name, relative) in manifest.dependencies {
        let path = dependency_path(root, &relative)?;
        dependencies.insert(
            name,
            LockedDependency {
                path: relative,
                sha256: hash_package(&path)?,
            },
        );
    }
    let lock = Lockfile {
        version: 1,
        dependencies,
    };
    encode_lock(&lock)
}

fn encode_lock<T: Serialize>(lock: &T) -> Result<Vec<u8>, String> {
    let mut contents =
        serde_json::to_vec_pretty(lock).map_err(|e| format!("cannot encode lockfile: {e}"))?;
    contents.push(b'\n');
    Ok(contents)
}

fn read_manifest(root: &Path) -> Result<Manifest, String> {
    let path = root.join("galeikan.json");
    let value: serde_json::Value = read_json(&path)?;
    let manifest = match value.get("version").and_then(|v| v.as_u64()) {
        Some(1) => Manifest::V1(
            serde_json::from_value(value)
                .map_err(|e| format!("invalid {}: {e}", path.display()))?,
        ),
        Some(2) => Manifest::V2(
            serde_json::from_value(value)
                .map_err(|e| format!("invalid {}: {e}", path.display()))?,
        ),
        _ => return Err("unsupported galeikan.json version".into()),
    };
    let names = match &manifest {
        Manifest::V1(value) => {
            if value.version != 1 {
                return Err("unsupported galeikan.json version".into());
            }
            value.dependencies.keys().collect::<Vec<_>>()
        }
        Manifest::V2(value) => value.dependencies.keys().collect::<Vec<_>>(),
    };
    if names.len() > 256 {
        return Err("too many project dependencies".into());
    }
    for name in names {
        if !valid_package_name(name) {
            return Err(format!("invalid package name {name}"));
        }
    }
    if let Manifest::V2(value) = &manifest {
        if value.version != 2 {
            return Err("unsupported galeikan.json version".into());
        }
        for dependency in value.dependencies.values() {
            validate_version(&dependency.version)?;
        }
        if let Some(package) = &value.package {
            if !valid_package_name(&package.name) {
                return Err(format!("invalid package name {}", package.name));
            }
            validate_version(&package.version)?;
        }
    }
    Ok(manifest)
}

fn build_lock_v2(
    root: &Path,
    manifest: &ManifestV2,
) -> Result<(LockfileV2, BTreeMap<String, PathBuf>), String> {
    let mut dependencies = BTreeMap::new();
    let mut packages = BTreeMap::new();
    let mut active = Vec::new();
    for (name, requested) in &manifest.dependencies {
        visit_dependency(
            root,
            name,
            requested,
            &mut dependencies,
            &mut packages,
            &mut active,
        )?;
    }
    Ok((
        LockfileV2 {
            version: 2,
            roots: manifest.dependencies.keys().cloned().collect(),
            dependencies,
        },
        packages,
    ))
}

fn visit_dependency(
    root: &Path,
    name: &str,
    requested: &VersionedDependency,
    locked: &mut BTreeMap<String, LockedDependencyV2>,
    packages: &mut BTreeMap<String, PathBuf>,
    active: &mut Vec<String>,
) -> Result<(), String> {
    if active.iter().any(|entry| entry == name) {
        return Err(format!("cyclic package dependency involving {name}"));
    }
    if let Some(existing) = locked.get(name) {
        if existing.path != requested.path || existing.version != requested.version {
            return Err(format!(
                "conflicting package {name}: {}@{} and {}@{}",
                existing.path, existing.version, requested.path, requested.version
            ));
        }
        return Ok(());
    }
    if locked.len() + active.len() >= 256 || active.len() >= 32 {
        return Err("package graph exceeds size or depth limit".into());
    }
    let path = dependency_path(root, &requested.path)?;
    let package_manifest = match read_manifest(&path)? {
        Manifest::V2(value) => value,
        Manifest::V1(_) => {
            return Err(format!("package {name} requires a version 2 galeikan.json"));
        }
    };
    let identity = package_manifest
        .package
        .as_ref()
        .ok_or_else(|| format!("package {name} has no package identity"))?;
    if identity.name != name || identity.version != requested.version {
        return Err(format!(
            "package {name} identity/version does not match the requested dependency"
        ));
    }
    if !source_module_path(&path, "main")?.is_file() {
        return Err(format!("package {name} has no main.gak or main.gaks"));
    }
    active.push(name.to_owned());
    for (child, dependency) in &package_manifest.dependencies {
        visit_dependency(root, child, dependency, locked, packages, active)?;
    }
    active.pop();
    let sha256 = hash_package(&path)?;
    packages.insert(name.to_owned(), path);
    locked.insert(
        name.to_owned(),
        LockedDependencyV2 {
            path: requested.path.clone(),
            version: requested.version.clone(),
            sha256,
            dependencies: package_manifest.dependencies.keys().cloned().collect(),
        },
    );
    Ok(())
}

fn validate_version(version: &str) -> Result<(), String> {
    let invalid = || format!("invalid exact package version {version}");
    let (without_build, build) = version.split_once('+').unwrap_or((version, ""));
    if version.contains('+') && !valid_identifiers(build, false) {
        return Err(invalid());
    }
    let (core, prerelease) = without_build.split_once('-').unwrap_or((without_build, ""));
    if without_build.contains('-') && !valid_identifiers(prerelease, true) {
        return Err(invalid());
    }
    let parts: Vec<_> = core.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || (part.len() > 1 && part.starts_with('0'))
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || part.parse::<u64>().is_err()
        })
    {
        return Err(invalid());
    }
    Ok(())
}

fn valid_identifiers(value: &str, prerelease: bool) -> bool {
    value.split('.').all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && (!prerelease
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || part.len() == 1
                || !part.starts_with('0'))
    })
}

fn read_lock(root: &Path) -> Result<Lockfile, String> {
    let path = root.join("galeikan.lock");
    read_json(&path).map_err(|e| format!("{e}; run galeikan lock <project>"))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?
        .take(MAX_MANIFEST + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.len() as u64 > MAX_MANIFEST {
        return Err(format!("{} exceeds 1 MiB", path.display()));
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid {}: {e}", path.display()))
}

fn valid_package_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !matches!(
            name,
            "std" | "py" | "pkg" | "for" | "in" | "let" | "var" | "fn"
        )
}

fn dependency_path(root: &Path, relative: &str) -> Result<PathBuf, String> {
    if relative.is_empty()
        || relative.len() > 4096
        || relative.contains('\\')
        || relative.contains(':')
    {
        return Err(format!("invalid dependency path {relative}"));
    }
    let mut candidate = root.to_path_buf();
    for part in relative.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(format!("invalid dependency path {relative}"));
        }
        candidate.push(part);
    }
    let canonical = candidate
        .canonicalize()
        .map_err(|e| format!("cannot read dependency {relative}: {e}"))?;
    if !canonical.starts_with(root) || !canonical.is_dir() {
        return Err(format!(
            "dependency {relative} must be a directory inside the project"
        ));
    }
    Ok(canonical)
}

fn hash_package(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    collect_files(root, root, 0, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    hasher.update(b"galeikan-package-v1\0");
    hasher.update((files.len() as u32).to_le_bytes());
    let mut total = 0_u64;
    for (relative, path) in files {
        let mut bytes = Vec::new();
        let remaining = MAX_PACKAGE_BYTES - total;
        fs::File::open(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?
            .take(remaining + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or("package size overflow")?;
        if total > MAX_PACKAGE_BYTES {
            return Err("package exceeds 64 MiB".into());
        }
        hasher.update((relative.len() as u32).to_le_bytes());
        hasher.update(relative.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn collect_files(
    root: &Path,
    dir: &Path,
    depth: usize,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), String> {
    if depth > 32 {
        return Err("package directory nesting too deep".into());
    }
    for entry in fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("cannot read package entry: {e}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("package symlink not allowed: {}", path.display()));
        }
        let canonical = path
            .canonicalize()
            .map_err(|e| format!("cannot resolve {}: {e}", path.display()))?;
        if !canonical.starts_with(root) {
            return Err(format!(
                "package path escapes dependency: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            collect_files(root, &path, depth + 1, out)?;
        } else if metadata.is_file() {
            if out.len() >= MAX_PACKAGE_FILES {
                return Err("package has too many files".into());
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "invalid package file path")?
                .components()
                .map(|c| c.as_os_str().to_str().ok_or("non-UTF-8 package path"))
                .collect::<Result<Vec<_>, _>>()?
                .join("/");
            out.push((relative, path));
        } else {
            return Err(format!("unsupported package entry: {}", path.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_version;

    #[test]
    fn exact_package_versions_follow_semver_shape() {
        for version in ["0.1.0", "12.3.45", "1.2.3-alpha.1", "1.2.3+build.007"] {
            assert!(validate_version(version).is_ok(), "{version}");
        }
        for version in [
            "",
            "1",
            "1.2",
            "01.2.3",
            "1.02.3",
            "1.2.-3",
            "1.2.3-alpha.01",
            "1.2.3+",
            "1.2.3.4",
            "^1.2.3",
        ] {
            assert!(validate_version(version).is_err(), "{version}");
        }
    }
}
