//! Qualification transport only: actual RightKit Scanner, embedded catalog & production
//! protected trust. No test trust loader, substitute catalog, source rules or admission.
//! Root integration builds this helper through managed CI, then explicitly pins its binary.
use legion_audit::native_providers::legacy::ownership_sdk::NativeOwner;
use rightkit_ownership::{ScanContext, Scanner, SystemClock};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, io::Read, path::Path, sync::Arc};

fn inventory(root: &Path) -> Result<Value, String> {
    let mut listed = rightkit_ownership::inventory::git_listed_inventory(
        root,
        &|_| true,
        &[],
        &|_| 64 * 1024 * 1024,
        root,
    );
    rightkit_ownership::inventory::listed_coverage(&mut listed);
    if !listed.coverage.is_empty() {
        return Err("actual owner input inventory is incomplete".into());
    }
    let mut files = BTreeMap::new();
    let mut total = 0;
    for file in listed.files {
        let mut path = root.to_path_buf();
        for component in Path::new(&file.rel).components() {
            if !matches!(component, std::path::Component::Normal(_)) {
                return Err("unsafe owner input path".into());
            }
            path.push(component.as_os_str());
            if fs::symlink_metadata(&path)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
            {
                return Err("owner input symlink".into());
            }
        }
        let mut bytes = Vec::new();
        fs::File::open(&path)
            .map_err(|e| e.to_string())?
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        total += bytes.len();
        if bytes.len() > 64 * 1024 * 1024 || total > 256 * 1024 * 1024 {
            return Err("owner input limit".into());
        }
        if files
            .insert(
                file.rel,
                format!("sha256:{}", rightkit_ownership::json::sha256_hex(&bytes)),
            )
            .is_some()
        {
            return Err("duplicate owner input path".into());
        }
    }
    rightkit_ownership::committed::assert_checkout_clean(root, None, None)
        .map_err(|e| e.message)?;
    let committed =
        rightkit_ownership::committed::acquire(root, None, None, &[]).map_err(|e| e.message)?;
    if !committed.coverage.is_empty() {
        return Err("actual owner committed coverage is incomplete".into());
    }
    let origin = committed.origin.as_ref().ok_or("owner origin is missing")?;
    let repository_identity = rightkit_ownership::canonical_repository_identity(&json!(origin))?;
    let content = rightkit_ownership::inventory::content_inventory(root);
    if !content.complete {
        return Err("actual owner content inventory is incomplete".into());
    }
    Ok(json!({"complete":true,"ownerContentDigest":content.digest,
        "sourceIdentity":{"root":root,"repositoryIdentity":repository_identity,"commit":committed.commit,"tree":committed.tree},
        "files":files.into_iter().map(|(path,digest)|json!({"path":path,"digest":digest})).collect::<Vec<_>>()}))
}

fn run() -> Result<Value, String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.is_empty() || args.len() > 2 || args.get(1).is_some_and(|v| v != "--inputs") {
        return Err("expected ROOT [--inputs]".into());
    }
    let root = fs::canonicalize(&args[0]).map_err(|e| e.to_string())?;
    let identity =
        NativeOwner::pin(&std::env::current_exe().map_err(|e| e.to_string())?)?.identity();
    let scanner = Scanner::with_embedded_catalog(ScanContext {
        clock: Arc::new(SystemClock),
        host: rightkit_ownership::host_string(),
        authority: rightkit_ownership::trust::production_authority_env(),
        trust_loader: rightkit_ownership::trust::production_trust_loader(),
        policy_digest: rightkit_ownership::scanner_policy_digest(),
        before_inventory: None,
    });
    let before = inventory(&root)?;
    let owner = if args.len() == 2 {
        scanner.inputs(&root)
    } else {
        scanner.scan(&root)
    };
    let after = inventory(&root)?;
    if before != after
        || (owner.get("inputs").is_some()
            && owner["inputs"]["contentDigest"] != after["ownerContentDigest"])
    {
        return Err("owner input inventory changed".into());
    }
    Ok(
        json!({"protocol":"legion-rightkit-ownership-native/1","root":root,"identity":identity,
        "inputInventory":after,"owner":owner}),
    )
}

fn main() {
    let output = run().unwrap_or_else(|error| json!({"error":error}));
    println!("{}", serde_json::to_string(&output).expect("JSON"));
}
