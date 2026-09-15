use super::{CommandError, CommandResult};
use clap::Args;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

const HARNESS_NAMES: [&str; 4] = ["claude-code", "codex", "gemini", "agents-md"];
const MARKER_START: &str = "<!-- legion:bind:start v1 -->";
const MARKER_END: &str = "<!-- legion:bind:end -->";
const TOML_START: &str = "# >>> legion:managed-block v1 >>>";
const TOML_END: &str = "# <<< legion:managed-block v1 <<<";
const ROSTER_SAGE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/roster/sage.md"));
const ROSTER_ALCHEMIST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/roster/alchemist.md"));
const ROSTER_ORACLE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/roster/oracle.md"));
const COVENANT_DOCTRINE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../doctrine/covenant-seat.md"));
const HOST_PROJECTION: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/host-projection.json"));

#[derive(Debug, Args)]
pub struct BindArgs {
    #[arg(default_value = ".")] pub root: PathBuf,
    #[arg(long)] pub json: bool,
    #[arg(long)] pub check: bool,
    #[arg(long)] pub write: bool,
    #[arg(long)] pub registrations: bool,
    #[arg(long = "harness")] pub harness: Vec<String>,
}

#[derive(Clone)] struct Target { path: PathBuf, kind: &'static str, reason: String, expected: String, write_content: String, skip_write: bool, conflicts: Vec<Value> }
struct HarnessPlan { targets: Vec<Target>, report: Value }

pub fn run(args: BindArgs) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(|_| CommandError::usage(format!("root does not exist: {}", args.root.display())))?;
    let root = super::display_path(&root);
    if args.registrations { return registrations_report(&root); }
    if args.check && args.write { return Err(CommandError::usage("bind accepts either --check or --write, not both")); }
    for name in &args.harness { if !HARNESS_NAMES.contains(&name.as_str()) { return Err(CommandError::usage(format!("unknown harness: {name} (expected one of {})", HARNESS_NAMES.join("|")))); } }
    let dry_run = !args.write;
    let names = if args.harness.is_empty() { detect_harnesses(&root) } else { args.harness.clone() };
    let receipt = read_json_file(&root.join(".legion").join("binding.json"));
    let mut plans = names.iter().map(|name| build_harness(&root, name, receipt.as_ref())).collect::<Vec<_>>();
    let has_conflicts = plans.iter().any(|p| p.targets.iter().any(|t| !t.conflicts.is_empty()));
    let has_drift = plans.iter().any(|p| p.report["drift"].as_array().is_some_and(|items| !items.is_empty()));
    let failed = (args.write && has_conflicts) || (args.check && (has_conflicts || has_drift));
    if args.write && !failed {
        for plan in &mut plans {
            let mut wrote = Vec::new();
            for target in &plan.targets { if target.skip_write { continue; } write_if_different(&target.path, &target.write_content)?; wrote.push(target.path.to_string_lossy().to_string()); }
            plan.report["wrote"] = json!(wrote);
        }
        let receipt_value = json!({"schemaVersion":2,"kind":"legion-binding-receipt","packageVersion":env!("CARGO_PKG_VERSION"),"harnesses":plans.iter().map(|p|json!({"name":p.report["name"],"fidelityTier":p.report["fidelityTier"],"files":p.report["artifacts"]})).collect::<Vec<_>>()});
        let path = root.join(".legion").join("binding.json");
        write_if_different(&path, &format!("{}\n", serde_json::to_string_pretty(&receipt_value).map_err(super::io_error)?))?;
    }
    let mut output = json!({"schemaVersion":1,"kind":if dry_run{"legion-bind-preview"}else{"legion-bind-result"},"root":root,"harnesses":plans.into_iter().map(|p|p.report).collect::<Vec<_>>(),"dryRun":dry_run});
    if failed { output["valid"] = json!(false); }
    Ok(output)
}

fn write_if_different(path: &Path, content: &str) -> Result<(), CommandError> { if std::fs::read_to_string(path).ok().as_deref()==Some(content){return Ok(());} if let Some(p)=path.parent(){std::fs::create_dir_all(p).map_err(super::io_error)?;} std::fs::write(path,content).map_err(super::io_error) }
fn detect_harnesses(root:&Path)->Vec<String>{
    let mut names = Vec::new();
    if root.join(".codex").exists() || root.join(".codex/config.toml").exists() {
        names.push("codex".into());
    }
    if root.join(".gemini").exists() || root.join("GEMINI.md").exists() {
        names.push("gemini".into());
    }
    names
}
fn build_harness(root:&Path,name:&str,receipt:Option<&Value>)->HarnessPlan{
    let (present,fidelity,retired,note,mut targets)=match name{
        "claude-code"=>(root.join(".claude").exists(),"retired",Some(true),Some("Claude Code is installed by the Legion plugin package, not by legion bind. Use the plugin (npm run plugin:dev for the live-source dev command); bind no longer writes .claude/ for Claude Code (one installation path owns each harness)."),Vec::new()),
        "codex"=>(root.join(".codex").exists()||root.join(".codex/agents").exists(),"full",None,None,codex_targets(root)),
        "gemini"=>(root.join(".gemini").exists()||root.join("GEMINI.md").exists(),"full",None,None,gemini_targets(root)),
        "agents-md"=>(root.join("AGENTS.md").exists()&&!root.join(".claude").exists(),"doctrine-only",None,None,vec![agents_target(root)]),
        _=>(false,"unknown",None,None,Vec::new()),};
    let prior=receipt.and_then(|r|r["harnesses"].as_array()).and_then(|rs|rs.iter().find(|h|h["name"].as_str()==Some(name)));
    let artifacts=targets.iter().map(|t|artifact(root,t)).collect::<Vec<_>>(); let drift=drift_for_harness(root,prior,&targets);
    let managed=targets.iter().filter(|t|!t.conflicts.is_empty()).map(|t|json!({"path":t.path,"conflicts":t.conflicts})).collect::<Vec<_>>();
    let mut report=json!({"name":name,"present":present,"fidelityTier":fidelity,"wouldWrite":targets.iter().map(|t|json!({"path":t.path,"reason":t.reason})).collect::<Vec<_>>(),"artifacts":artifacts,"drift":drift,"managedConflicts":managed});
    if retired.is_some(){report["retired"]=json!(true);} if let Some(n)=note{report["note"]=json!(n);}
    for t in &mut targets{if !t.conflicts.is_empty(){t.skip_write=true;}}
    HarnessPlan{targets,report}
}
fn artifact(root:&Path,target:&Target)->Value{let mut h=Sha256::new();h.update(target.expected.as_bytes());json!({"path":relative_path(root,&target.path),"kind":target.kind,"bytes":target.expected.len(),"digest":format!("sha256:{}",hex::encode(h.finalize()))})}
fn artifact_text(text:&str)->Value{let mut h=Sha256::new();h.update(text.as_bytes());json!({"bytes":text.len(),"digest":format!("sha256:{}",hex::encode(h.finalize()))})}
fn relative_path(root:&Path,path:&Path)->String{path.strip_prefix(root).unwrap_or(path).to_string_lossy().replace('\\',"/")}
fn drift_for_harness(root:&Path,prior:Option<&Value>,targets:&[Target])->Vec<Value>{let Some(files)=prior.and_then(|h|h["files"].as_array())else{return Vec::new()};files.iter().filter_map(|record|{let path=record.as_str().or_else(||record["path"].as_str())?;let target=targets.iter().find(|t|relative_path(root,&t.path)==path)?;let disk=root.join(path.replace('/',std::path::MAIN_SEPARATOR_STR));if !disk.is_file(){return Some(json!({"path":path,"kind":"missing"}));}let raw=std::fs::read_to_string(disk).unwrap_or_default();let actual=if target.kind=="marker"{extract_marker(&raw)}else{Some(raw)}?;let observed=artifact_text(&actual);let expected=artifact(root,target);if observed["digest"]!=expected["digest"]||observed["bytes"]!=expected["bytes"]{return Some(json!({"path":path,"kind":if target.kind=="marker"{"stale-marker"}else{"modified"},"expected":expected,"observed":observed}));}if record.is_object()&&(record["digest"]!=observed["digest"]||record["bytes"]!=observed["bytes"]){return Some(json!({"path":path,"kind":"receipt-digest-mismatch","expected":record,"observed":observed}));}None}).collect()}
fn marker_block(content:&str)->String{format!("{MARKER_START}\n{}\n{MARKER_END}",content.trim())}
fn extract_marker(text:&str)->Option<String>{let s=text.find(MARKER_START)?;let e=text[s..].find(MARKER_END)?+s+MARKER_END.len();Some(text[s..e].into())}
fn upsert_marker(existing:&str,content:&str)->String{let block=marker_block(content);if let Some(s)=existing.find(MARKER_START){if let Some(e0)=existing[s..].find(MARKER_END){let e=s+e0+MARKER_END.len();return format!("{}{}{}",&existing[..s],block,&existing[e..]);}}if existing.is_empty(){format!("{block}\n")}else{format!("{}{sep}{block}\n",existing,sep=if existing.ends_with('\n'){"\n"}else{"\n\n"})}}
fn target_marker(path:PathBuf,reason:String,block:String)->Target{let existing=std::fs::read_to_string(&path).unwrap_or_default();Target{path,kind:"marker",reason,expected:marker_block(&block),write_content:upsert_marker(&existing,&block),skip_write:false,conflicts:Vec::new()}}
fn target_whole(path:PathBuf,reason:String,content:String)->Target{Target{path,kind:"whole",reason,expected:content.clone(),write_content:content,skip_write:false,conflicts:Vec::new()}}

#[derive(Clone)]struct Role{name:String,description:String,tier:String}
fn role(id:&str)->Role{let source=match id{"sage"=>ROSTER_SAGE,"alchemist"=>ROSTER_ALCHEMIST,_=>ROSTER_ORACLE};let(f,_)=frontmatter(source);Role{name:id.into(),description:f.get("description").cloned().unwrap_or_default(),tier:f.get("modelTier").cloned().unwrap_or_default()}}
fn frontmatter(source:&str)->(HashMap<String,String>,String){let n=source.replace("\r\n","\n");let mut it=n.split('\n');let mut f=HashMap::new();if it.next().map(str::trim)!=Some("---"){return(f,n.trim().into())}let mut body=String::new();let mut closed=false;for line in it{if !closed&&line.trim()=="---"{closed=true;continue}if !closed{if let Some((k,v))=line.split_once(':'){f.insert(k.trim().into(),v.trim().into());}}else{body.push_str(line);body.push('\n')}}(f,body.trim().into())}
fn markdown_section(body:&str,wanted:&str)->Option<String>{let ls=body.lines().collect::<Vec<_>>();let start=ls.iter().position(|l|l.trim_start().eq_ignore_ascii_case(&format!("## {wanted}")))?+1;let end=ls[start..].iter().position(|l|l.trim_start().starts_with("## ")).map(|i|start+i).unwrap_or(ls.len());Some(format!("## {wanted}\n\n{}",ls[start..end].join("\n").trim()))}
fn title_case(value:&str)->String{let mut c=value.chars();match c.next(){Some(x)=>x.to_uppercase().collect::<String>()+c.as_str(),None=>String::new()}}
fn role_projection(id:&str)->String{let source=match id{"sage"=>ROSTER_SAGE,"alchemist"=>ROSTER_ALCHEMIST,_=>ROSTER_ORACLE};let(f,b)=frontmatter(source);let name=f.get("name").cloned().unwrap_or_else(||id.into());let desc=f.get("description").cloned().unwrap_or_default();let tier=f.get("modelTier").cloned().unwrap_or_default();let route=match id{"sage"=>"doctrine/sage.md","alchemist"=>"doctrine/alchemist.md",_=>"doctrine/oracle.md"};let sections=["Purpose","Triggers","Routes","Capabilities","Inputs","Outputs","Boundaries","Handoffs","Evidence rules","Model policy"].iter().filter_map(|s|markdown_section(&b,s)).collect::<Vec<_>>();format!("---\nname: {name}\ndescription: {desc}\n---\n\n# {} — Legion role\n\nModel tier: `{tier}`. Host resolves a compatible provider/model; roster source is vendor-neutral.\n\nRoute method: `{route}`.\n\n{}\n",title_case(&name),sections.join("\n\n"))}
fn capability_catalog()->String{let v:Value=serde_json::from_str(HOST_PROJECTION).unwrap_or_default();let rows=v["capabilities"].as_array().cloned().unwrap_or_default().into_iter().filter(|c|c["kind"]=="domain-capability"&&c["discoverability"]=="public").map(|c|format!("- **{}** — {}",c["name"].as_str().unwrap_or_default(),c["description"].as_str().unwrap_or_default())).collect::<Vec<_>>();if rows.is_empty(){String::new()}else{format!("## Legion capabilities\n\n{}",rows.join("\n"))}}
fn json_string(v:&str)->String{serde_json::to_string(v).unwrap()}

fn gemini_targets(root: &Path) -> Vec<Target> {
    let ids = ["sage", "alchemist", "oracle"];
    let commands = ids
        .iter()
        .map(|id| format!("/legion:{id}"))
        .collect::<Vec<_>>()
        .join(", ");
    let lines = ids
        .iter()
        .map(|id| {
            let r = role(id);
            format!("- **{}**: {} Tier: `{}`.", r.name, r.description, r.tier)
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut out = vec![target_marker(
        root.join("GEMINI.md"),
        "install Legion role context for Gemini CLI".into(),
        format!("# Legion\n\nUse native Legion role commands: {commands}.\n\n{lines}\n- **Covenant seat**: advisory doctrine role, not an authority."),
    )];
    for id in ids {
        let r = role(id);
        let p = format!(
            "{}\n\nApply this role to the user request:\n{{{{args}}}}",
            role_projection(id)
        );
        out.push(target_whole(
            root.join(format!(".gemini/commands/legion/{id}.toml")),
            format!("install Gemini /legion:{id} role command"),
            format!(
                "description = {}\nprompt = {}\n",
                json_string(&r.description),
                json_string(&p)
            ),
        ));
    }
    let covenant = frontmatter(COVENANT_DOCTRINE)
        .0
        .get("description")
        .cloned()
        .unwrap_or_default();
    let p = format!(
        "{}\n\nReview this immutable packet only:\n{{{{args}}}}",
        COVENANT_DOCTRINE
    );
    out.push(target_whole(
        root.join(".gemini/commands/legion/covenant-seat.toml"),
        "install Gemini /legion:covenant-seat role command".into(),
        format!(
            "description = {}\nprompt = {}\n",
            json_string(&covenant),
            json_string(&p)
        ),
    ));
    let path = root.join(".gemini/settings.json");
    let mut old = read_json_file(&path).unwrap_or_else(|| json!({}));
    migrate_mcp_servers(&mut old);
    let mut obj = old.as_object().cloned().unwrap_or_default();
    let mut servers = obj
        .remove("mcpServers")
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    servers.insert(
        "legion".into(),
        json!({"command":"legion","args":["serve","--stdio"]}),
    );
    obj.insert("mcpServers".into(), Value::Object(servers));
    out.push(target_whole(
        path,
        "register Legion MCP server in Gemini project settings".into(),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&Value::Object(obj)).unwrap()
        ),
    ));
    out
}
fn agents_target(root:&Path)->Target{let roles=["sage","alchemist","oracle"].iter().map(|id|{let r=role(id);format!("- **{}** — {} Model tier: `{}`.",r.name,r.description,r.tier)}).collect::<Vec<_>>().join("\n");let cat=capability_catalog();let block=format!("# Legion authority context\n\n{roles}\n- **Covenant seat** — doctrine-only advisory review seat; not an authority.\n\nUse Legion routing. Do not edit generated harness files; rerun `legion bind --write`.{}",if cat.is_empty(){String::new()}else{format!("\n\n{cat}")});target_marker(root.join("AGENTS.md"),"install low-fidelity Legion authority context and capability catalog in AGENTS.md".into(),block)}

fn codex_targets(root:&Path)->Vec<Target>{let mut out=Vec::new();for id in ["sage","alchemist","oracle"]{let content=format!("# Generated by Legion bind. Do not edit; re-run `legion bind --write`.\nname = {}\ndeveloper_instructions = {}\n\n",json_string(id),json_string(&role_projection(id)));out.push(target_whole(root.join(format!(".codex/agents/{id}.toml")),format!("install {id} agent projection under .codex/agents/"),content));}let content=format!("# Generated by Legion bind. Do not edit; re-run `legion bind --write`.\nname = {}\ndeveloper_instructions = {}\n\n",json_string("covenant-seat"),json_string(COVENANT_DOCTRINE));out.push(target_whole(root.join(".codex/agents/covenant-seat.toml"),"install covenant-seat agent projection under .codex/agents/".into(),content));let path=root.join(".codex/config.toml");let raw=std::fs::read_to_string(&path).unwrap_or_default();let(existing,conf)=migrate_legacy_config(&raw);let target=if let Some(c)=conf{Target{path:path.clone(),kind:"toml-managed",reason:"install Legion agent projections and MCP entry in .codex/config.toml".into(),expected:raw.clone(),write_content:raw,skip_write:true,conflicts:c}}else{match upsert_managed(&existing,&generated_header(),&config_inner()){Ok((c,_))=>Target{path:path.clone(),kind:"toml-managed",reason:"install Legion agent projections and MCP entry in .codex/config.toml".into(),expected:c.clone(),skip_write:c==raw,write_content:c,conflicts:Vec::new()},Err(c)=>Target{path:path.clone(),kind:"toml-managed",reason:"install Legion agent projections and MCP entry in .codex/config.toml".into(),expected:raw.clone(),write_content:raw,skip_write:true,conflicts:c}}};out.push(target);out}
fn config_inner()->String{let mut t=Vec::new();for id in ["sage","alchemist","oracle"]{let r=role(id);t.push(format!("[agents.{id}]\ndescription = {}\nconfig_file = {}\n",json_string(&r.description),json_string(&format!("agents/{id}.toml"))));}let covenant=frontmatter(COVENANT_DOCTRINE).0.get("description").cloned().unwrap_or_default();t.push(format!("[agents.covenant-seat]\ndescription = {}\nconfig_file = \"agents/covenant-seat.toml\"\n",json_string(&covenant)));t.join("\n")}
fn generated_header()->String{"# Generated by Legion bind.\n# Owned keys: [agents.sage], [agents.alchemist], [agents.oracle], [agents.covenant-seat].\n# Everything outside the legion:managed-block markers below is the user's file.".into()}
fn owned_headers()->Vec<String>{["[agents.sage]","[agents.alchemist]","[agents.oracle]","[agents.covenant-seat]","[mcp_servers.legion]"].iter().map(|s|(*s).into()).collect()}
fn legacy_headers()->HashSet<String>{["sage","alchemist","oracle","arcane","forge","sorcerer","seer","sentinel"].iter().map(|s|format!("[agents.{s}]")).chain(std::iter::once("[agents.covenant-seat]".into())).chain(std::iter::once("[mcp_servers.legion]".into())).collect()}
fn extract_owned(text:&str)->Vec<(String,Vec<String>)>{let owned=owned_headers();let mut result=Vec::new();let mut current:Option<(String,Vec<String>)>=None;for line in text.lines(){let t=line.trim_start();if t.starts_with('['){if let Some(x)=current.take(){result.push(x);}if let Some(i)=t.find(']'){let h=t[..=i].into();if owned.contains(&h){current=Some((h,Vec::new()));}}}else if let Some((_,b))=current.as_mut(){b.push(line.into());}}if let Some(x)=current{result.push(x)}result}
fn norm_body(body:&[String])->String{let mut e=body.len();while e>0&&body[e-1].trim().is_empty(){e-=1;}body[..e].iter().map(|s|s.trim_end()).collect::<Vec<_>>().join("\n")}
fn managed_block(inner:&str)->String{format!("{TOML_START}\n{}\n{TOML_END}",inner.trim())}
fn managed_document(header:&str,inner:&str)->String{format!("{header}\n{}\n",managed_block(inner))}
fn annotate_existing(text:&str)->String{let owned=owned_headers();let mut out:Vec<String>=Vec::new();let mut in_owned=false;for line in text.lines(){let t=line.trim_start();if t.starts_with('['){let yes=t.find(']').is_some_and(|i|owned.iter().any(|h|h==&t[..=i]));if yes&&!in_owned{out.push(TOML_START.into());in_owned=true;}if !yes&&in_owned{out.push(TOML_END.into());in_owned=false;}}out.push(line.into());}if in_owned{out.push(TOML_END.into());}out.join("\n")}
fn replace_toml_marker(text:&str,new_block:&str)->String{let Some(s)=text.find(TOML_START)else{return text.into()};let Some(e0)=text[s..].find(TOML_END)else{return text.into()};let e=s+e0+TOML_END.len();format!("{}{}{}",&text[..s],new_block,&text[e..])}
fn upsert_managed(existing:&str,header:&str,inner:&str)->Result<(String,String),Vec<Value>>{let next=managed_block(inner);if !(existing.contains(TOML_START)&&existing.contains(TOML_END)){let ex=extract_owned(existing);if ex.is_empty(){return Ok((if existing.is_empty(){managed_document(header,inner)}else{format!("{}{}\n{}",existing,if existing.ends_with('\n'){""}else{"\n"},managed_document(header,inner))},"written".into()));}let generated=extract_owned(&next);let map=ex.iter().map(|x|(x.0.clone(),x.1.clone())).collect::<HashMap<_,_>>();let mut c=Vec::new();for(h,b)in &generated{match map.get(h){Some(old)if norm_body(old)==norm_body(b)=>{},Some(old)=>c.push(json!({"header":h,"kind":"legion_owned_header_differs_in_existing","existingBody":norm_body(old),"generatedBody":norm_body(b)})),None=>c.push(json!({"header":h,"kind":"legion_owned_header_missing_in_existing"}))}}for(h,_)in &ex{if !generated.iter().any(|x|x.0==*h){c.push(json!({"header":h,"kind":"legion_owned_header_extra_in_existing"}));}}if !c.is_empty(){return Err(c)}return Ok((format!("{}\n{}",annotate_existing(existing),managed_document(header,inner)),"adopted_with_marker".into()));}let replaced=replace_toml_marker(existing,&next);Ok((replaced.clone(),if replaced==existing{"unchanged".into()}else{"replaced".into()}))}

fn migrate_legacy_config(raw:&str)->(String,Option<Vec<Value>>){let(assurance,conf)=assurance_migration(raw);if conf.is_some(){return(raw.into(),conf)}let managed=assurance.contains(TOML_START)&&assurance.contains(TOML_END);let aliases=["forge","sorcerer","seer","sentinel"];let legacy=aliases.iter().any(|id|assurance.lines().any(|l|l.trim()==format!("[agents.{id}]")));let generated=!managed&&assurance.contains("# Generated by Legion bind.")&&legacy_headers().iter().any(|h|assurance.lines().any(|l|l.trim()==h));if !managed&&!legacy&&!generated{return(assurance,None)}let mut out=Vec::new();let mut drop=false;let mut inside=false;for line in assurance.lines(){if line.contains(TOML_START){inside=true;drop=false;out.push(line);continue}if line.contains(TOML_END){inside=false;drop=false;out.push(line);continue}let t=line.trim_start();if t.starts_with('['){if let Some(i)=t.find(']'){let h=&t[..=i];drop=!inside&&(if managed{h=="[mcp_servers.legion]"}else{legacy_headers().contains(h)});}}if !drop{out.push(line)}}(format!("{}\n",out.join("\n").trim()),None)}
fn assurance_migration(raw:&str)->(String,Option<Vec<Value>>){let target="[mcp_servers.seer]";let ls=raw.lines().collect::<Vec<_>>();let mut spans=Vec::new();let mut i=0;while i<ls.len(){if ls[i].trim()==target{let s=i;i+=1;while i<ls.len()&&!ls[i].trim_start().starts_with('[')&&!ls[i].contains(TOML_START){i+=1}spans.push((s,i))}else{i+=1}}if spans.is_empty(){return(raw.into(),None)}let mut c=Vec::new();for(s,e)in&spans{let body=&ls[s+1..*e];let cmd=body.iter().find(|l|l.trim_start().starts_with("command =")).and_then(|l|l.split_once('=').map(|x|x.1.trim().trim_matches('"')));let owned=cmd.is_some_and(|x|x=="python"||x=="python3")&&body.iter().any(|l|l.contains("legion_kernel.adapters.mcp_server"));if !owned{c.push(json!({"header":target,"kind":"legacy_assurance_binding_not_legion_owned"}))}}if !c.is_empty(){return(raw.into(),Some(c))}let removed=spans.into_iter().flat_map(|(s,e)|s..e).collect::<HashSet<_>>();(ls.into_iter().enumerate().filter_map(|(i,l)|(!removed.contains(&i)).then_some(l)).collect::<Vec<_>>().join("\n"),None)}
fn migrate_mcp_servers(value:&mut Value){let Some(obj)=value.as_object_mut()else{return};let key=if obj.get("mcp_servers").is_some_and(Value::is_object){"mcp_servers"}else if obj.get("mcpServers").is_some_and(Value::is_object){"mcpServers"}else{return};let Some(servers)=obj.get_mut(key).and_then(Value::as_object_mut)else{return};let Some(seer)=servers.get("seer").cloned()else{return};let owned=seer["command"].as_str().is_some_and(|x|x=="python"||x=="python3")&&seer["args"].as_array().is_some_and(|a|a.windows(2).any(|w|w[0]=="-m"&&w[1]=="legion_kernel.adapters.mcp_server"));if owned{if !servers.contains_key("oracle"){servers.insert("oracle".into(),seer.clone());servers.remove("seer");}else if servers["oracle"]==seer{servers.remove("seer");}}}
fn read_json_file(path:&Path)->Option<Value>{serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()}

fn registrations_report(root:&Path)->CommandResult{let home=home_dir();let e=enumerate_registrations(&home,Some(root));let d=e["duplicates"].as_array().is_some_and(|x|!x.is_empty());let mut o=json!({"schemaVersion":1,"kind":"legion-bind-registrations","root":root,"sources":e["sources"],"registrations":e["registrations"],"duplicates":e["duplicates"]});if d{o["status"]=json!("policy-fail");}Ok(o)}
fn home_dir()->PathBuf{std::env::var_os("USERPROFILE").map(PathBuf::from).or_else(||std::env::var_os("HOME").map(PathBuf::from)).unwrap_or_else(||PathBuf::from("."))}
fn enumerate_registrations(home:&Path,root:Option<&Path>)->Value{let mut r=Vec::new();let mut s=Vec::new();settings_source(&home.join(".claude/settings.json"),"user-settings",&mut r,&mut s);if let Some(root)=root{settings_source(&root.join(".claude/settings.json"),"project-settings",&mut r,&mut s);settings_source(&root.join(".claude/settings.local.json"),"project-local-settings",&mut r,&mut s)}skills_dir_plugins(home,&mut r,&mut s);marketplace_plugins(home,&mut r,&mut s);let mut g:BTreeMap<String,Vec<Value>>=BTreeMap::new();for e in &r{g.entry(format!("{}::{}",e["event"].as_str().unwrap_or_default(),e["handler"].as_str().unwrap_or_default())).or_default().push(e.clone())}let mut d=Vec::new();for(k,es)in g{let src=es.iter().filter_map(|e|e["source"].as_str()).collect::<BTreeSet<_>>();if es.len()>1&&src.len()>1{let p=k.splitn(2,"::").collect::<Vec<_>>();let sources=src.into_iter().collect::<Vec<_>>();d.push(json!({"event":p[0],"handler":p.get(1).copied().unwrap_or_default(),"count":es.len(),"sources":sources,"detail":format!("{} runs {}x on {} (from {})",p.get(1).copied().unwrap_or_default(),es.len(),p[0],sources.join(" + "))}))}}r.sort_by_key(|e|format!("{}{}{}",e["event"],e["handler"],e["source"]));d.sort_by_key(|e|e["detail"].as_str().unwrap_or_default().to_owned());json!({"sources":s,"registrations":r,"duplicates":d})}
fn settings_source(path:&Path,source:&str,out:&mut Vec<Value>,sources:&mut Vec<Value>){if !path.is_file(){return}let Some(v)=read_json_file(path)else{return};sources.push(json!({"source":source,"path":path,"kind":"settings"}));from_hooks(v.get("hooks"),source,path,out)}
fn from_hooks(hooks:Option<&Value>,source:&str,path:&Path,out:&mut Vec<Value>){let Some(h)=hooks.and_then(Value::as_object)else{return};for(event,rows)in h{for row in rows.as_array().into_iter().flatten(){for hook in row["hooks"].as_array().into_iter().flatten(){let args=hook["args"].as_array().map(|a|a.iter().filter_map(Value::as_str).collect::<Vec<_>>()).unwrap_or_default();out.push(json!({"event":event,"handler":handler_id(hook["command"].as_str(),&args),"source":source,"sourcePath":path}))}}}}
fn plugin_source(dir:&Path,source:&str,out:&mut Vec<Value>,sources:&mut Vec<Value>){let m=dir.join(".claude-plugin/plugin.json");let h=dir.join("hooks/hooks.json");if !m.is_file()||!h.is_file(){return}let Some(v)=read_json_file(&h)else{return};sources.push(json!({"source":source,"path":h,"kind":"plugin"}));from_hooks(if v.get("hooks").is_some(){v.get("hooks")}else{Some(&v)},source,&h,out)}
fn skills_dir_plugins(home:&Path,out:&mut Vec<Value>,sources:&mut Vec<Value>){if let Ok(es)=std::fs::read_dir(home.join(".claude/skills")){for e in es.flatten(){if e.path().is_dir(){let n=e.file_name().to_string_lossy().into_owned();plugin_source(&e.path(),&format!("plugin:{n}@skills-dir"),out,sources)}}}}
fn marketplace_plugins(home:&Path,out:&mut Vec<Value>,sources:&mut Vec<Value>){let Some(v)=read_json_file(&home.join(".claude/plugins/installed_plugins.json"))else{return};for(name,rows)in v["plugins"].as_object().into_iter().flatten(){for row in rows.as_array().into_iter().flatten(){if let Some(p)=row["installPath"].as_str(){plugin_source(Path::new(p),&format!("plugin:{name}"),out,sources)}}}}
fn handler_id(command:Option<&str>,args:&[&str])->String{let text=command.unwrap_or_default().replace('\\',"/");if text.contains("rhook"){return format!("rhook {}",args.join(" ")).trim().into()}if text.contains("legion-hook"){return "legion-hook".into()}for t in text.split(|c:char|c.is_whitespace()||c=='"'||c=='\''){if [".py",".mjs",".cjs",".js"].iter().any(|x|t.ends_with(x)){return Path::new(t).file_name().and_then(|x|x.to_str()).unwrap_or(t).into()}}text.chars().take(60).collect::<String>().trim().into()}
