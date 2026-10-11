pub mod capabilities;
pub mod route_resources;
pub mod skill_frontmatter;

/// Lists a directory's entries as `(name, file type)`. Any unreadable entry,
/// non-UTF-8 name, or failed file-type lookup is an error: a generator must
/// never treat a directory it could not fully read as if it were complete.
pub fn read_dir_entries(dir: &std::path::Path) -> Result<Vec<(String, std::fs::FileType)>, String> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|raw| format!("{}: entry name is not UTF-8: {raw:?}", dir.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|e| format!("{}/{name}: {e}", dir.display()))?;
        out.push((name, file_type));
    }
    Ok(out)
}
