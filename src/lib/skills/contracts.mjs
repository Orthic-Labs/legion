const URI = /^legion-skill:\/\/([a-z0-9-]+)\/(.*)$/;
const SHA=/^sha256:[a-f0-9]{64}$/;const LICENSES=new Set(['unresolved','user-owned-supplied','licensed','public-domain']);
export function validateSkillBundle(bundle) {
  if(bundle?.schemaVersion!==1)throw new TypeError(`skill bundle unsupported schema version: ${bundle?.schemaVersion}`);
  if(!bundle?.id||!bundle.version||!bundle.entry||!bundle.provenance)throw new TypeError('skill bundle requires id version entry and provenance');
  if(!LICENSES.has(bundle.licenseState))throw new TypeError('skill bundle license state is invalid');
  if(bundle.licenseState==='unresolved'&&bundle.rightsReceipt!==null)throw new TypeError('unresolved skill rights cannot have a receipt');
  if(bundle.licenseState!=='unresolved'&&!bundle.rightsReceipt)throw new TypeError('resolved skill rights require a receipt');
  const root=`legion-skill://${bundle.id}/`;if(bundle.rootUri!==root)throw new TypeError('skill root must match bundle-owned legion-skill URI');
  if(!bundle.profiles?.audit||!bundle.profiles?.authoring)throw new TypeError('skill bundle requires audit and authoring profiles');
  if(bundle.profiles.audit.mutation!==false||bundle.profiles.audit.publish!==false)throw new TypeError('audit profile cannot grant mutation or publish');
  const paths=new Set(),uris=new Set();for(const file of bundle.files??[]){if(!file.path||file.path.startsWith('/')||file.path.split('/').includes('..'))throw new TypeError('skill file outside root');if(paths.has(file.path))throw new TypeError(`duplicate skill file: ${file.path}`);paths.add(file.path);const match=URI.exec(file.uri??'');if(!match||match[1]!==bundle.id||match[2]!==file.path)throw new TypeError(`skill URI must match bundle path: ${file.uri}`);if(uris.has(file.uri))throw new TypeError(`duplicate skill URI: ${file.uri}`);uris.add(file.uri);if(!SHA.test(file.sourceDigest??'')||!SHA.test(file.outputDigest??''))throw new TypeError(`skill source/output digest missing: ${file.path}`);if(!Array.isArray(file.transformations))throw new TypeError(`skill transformations missing: ${file.path}`);}
  if(!paths.has(bundle.entry))throw new TypeError(`skill entry missing: ${bundle.entry}`);return bundle;
}
