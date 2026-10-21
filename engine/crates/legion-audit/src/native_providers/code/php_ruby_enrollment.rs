//! Pure filesystem replay of CI-enrolled runtime bytes. No discovery process,
//! installer, network call, or authority to execute project code.
use super::*;
use std::{collections::VecDeque, io::Read};

fn file_digest(path: &Path, total: &mut u64) -> Result<String, String> {
    let metadata = std::fs::metadata(path).map_err(|_| "php-ruby-runtime-metadata")?;
    *total = total
        .checked_add(metadata.len())
        .filter(|v| *v <= 16 * 1024 * 1024 * 1024)
        .ok_or("php-ruby-runtime-byte-budget")?;
    let mut file = std::fs::File::open(path).map_err(|_| "php-ruby-runtime-read")?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| "php-ruby-runtime-read")?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("sha256:{}", hex::encode(hash.finalize())))
}

fn resolve(path: &Path, links: &Map<String, Value>) -> Result<PathBuf, String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err("php-ruby-runtime-relative".into());
    }
    let mut pending = path
        .components()
        .filter_map(|p| match p {
            Component::Normal(p) => Some(p.to_os_string()),
            _ => None,
        })
        .collect::<VecDeque<_>>();
    let mut current = PathBuf::from("/");
    let mut hops = 0;
    while let Some(part) = pending.pop_front() {
        if part == "." {
            continue;
        }
        if part == ".." {
            current.pop();
            continue;
        }
        current.push(part);
        let metadata =
            std::fs::symlink_metadata(&current).map_err(|_| "php-ruby-runtime-component")?;
        let key = current.to_string_lossy().trim_start_matches('/').to_owned();
        if metadata.file_type().is_symlink() {
            hops += 1;
            if hops > 40 {
                return Err("php-ruby-runtime-link-cycle".into());
            }
            let raw = std::fs::read_link(&current).map_err(|_| "php-ruby-runtime-link")?;
            if links.get(&key).and_then(Value::as_str) != raw.to_str() {
                return Err("php-ruby-runtime-unsealed-link".into());
            }
            current.pop();
            if raw.is_absolute() {
                current = PathBuf::from("/");
            }
            let mut parts = raw
                .components()
                .filter_map(|p| match p {
                    Component::Normal(p) => Some(p.to_os_string()),
                    Component::ParentDir => Some("..".into()),
                    Component::CurDir => Some(".".into()),
                    _ => None,
                })
                .collect::<VecDeque<_>>();
            parts.append(&mut pending);
            pending = parts;
        } else if links.contains_key(&key) {
            return Err("php-ruby-runtime-link-changed".into());
        }
    }
    Ok(current)
}

pub(super) fn replay(runtime: &Value, project: &Path) -> Result<Value, String> {
    if runtime["root"] != "/" || runtime["exclusions"] != json!([]) {
        return Err("php-ruby-runtime-boundary".into());
    }
    let roots = runtime["roots"]
        .as_array()
        .ok_or("php-ruby-runtime-roots")?;
    let expected = runtime["files"]
        .as_object()
        .ok_or("php-ruby-runtime-files")?;
    let links = runtime["links"]
        .as_object()
        .ok_or("php-ruby-runtime-links")?;
    let absent = runtime["absent"]
        .as_array()
        .ok_or("php-ruby-runtime-absent")?;
    if roots.is_empty() || expected.is_empty() || expected.len() + links.len() > 250000 {
        return Err("php-ruby-runtime-budget".into());
    }
    let project = project
        .canonicalize()
        .map_err(|_| "php-ruby-runtime-project")?;
    let mut files = BTreeMap::new();
    let mut observed_links = BTreeMap::new();
    let mut total = 0u64;
    let mut previous = String::new();
    for root in roots {
        let raw = root.as_str().ok_or("php-ruby-runtime-root")?;
        let root = Path::new(raw);
        if raw <= previous.as_str()
            || !root.is_absolute()
            || root.starts_with(&project)
            || resolve(root, links)? != root
        {
            return Err("php-ruby-runtime-root-boundary".into());
        }
        previous = raw.into();
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            let entry = entry.map_err(|_| "php-ruby-runtime-walk")?;
            let path = entry.path();
            let key = path.to_string_lossy().trim_start_matches('/').to_owned();
            if entry.file_type().is_symlink() {
                let raw = std::fs::read_link(path).map_err(|_| "php-ruby-runtime-link")?;
                observed_links.insert(
                    key,
                    Value::String(raw.to_str().ok_or("php-ruby-runtime-link-utf8")?.into()),
                );
            } else if entry.file_type().is_file() {
                resolve(path, links)?;
                files.insert(key, Value::String(file_digest(path, &mut total)?));
            } else if !entry.file_type().is_dir() {
                return Err("php-ruby-runtime-special-file".into());
            }
            if files.len() + observed_links.len() > 250000 {
                return Err("php-ruby-runtime-node-budget".into());
            }
        }
    }
    for (key, target) in links {
        if !safe(key) {
            return Err("php-ruby-runtime-link-path".into());
        }
        let path = Path::new("/").join(key);
        let raw = std::fs::read_link(&path).map_err(|_| "php-ruby-runtime-link-missing")?;
        if raw.to_str() != target.as_str() {
            return Err("php-ruby-runtime-link-changed".into());
        }
        let final_path = resolve(&path, links)?;
        // A sealed link stays inside the closure when it reaches an enrolled
        // file, a declared root (an empty root such as a pecl directory holds
        // no file), or when an absence probe is evaluated through it.
        let anchored = expected.keys().any(|file| {
            let file = Path::new("/").join(file);
            file == final_path || file.starts_with(&final_path)
        }) || roots.iter().filter_map(Value::as_str).any(|root| {
            let root = Path::new(root);
            root == final_path || root.starts_with(&final_path)
        }) || absent
            .iter()
            .filter_map(Value::as_str)
            .any(|probe| Path::new(probe).starts_with(&path));
        if !anchored {
            return Err("php-ruby-runtime-link-outside-closure".into());
        }
        observed_links.insert(key.clone(), target.clone());
    }
    for path in absent {
        let path = Path::new(path.as_str().ok_or("php-ruby-runtime-absent-path")?);
        if !path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
            || std::fs::symlink_metadata(path).is_ok()
        {
            return Err("php-ruby-runtime-earlier-load-candidate-created".into());
        }
    }
    if serde_json::to_value(&files).map_err(|_| "php-ruby-runtime-json")? != runtime["files"]
        || serde_json::to_value(&observed_links).map_err(|_| "php-ruby-runtime-json")?
            != runtime["links"]
    {
        return Err("php-ruby-runtime-tree-changed".into());
    }
    let digest = sha256_text(
        &serde_json::to_vec(
            &json!({"absent":absent,"files":files,"links":observed_links,"roots":roots}),
        )
        .map_err(|_| "php-ruby-runtime-json")?,
    );
    if runtime["digest"] != digest {
        return Err("php-ruby-runtime-digest".into());
    }
    Ok(json!({"digest":digest,"files":files.len(),"links":observed_links.len(),"roots":roots}))
}
