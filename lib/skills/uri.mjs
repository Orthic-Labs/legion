const URI = /^legion-skill:\/\/([a-z0-9-]+)\/([^?#]+)$/;
export function parseSkillUri(uri) { const match = URI.exec(uri); if (!match) throw new TypeError(`unsupported skill URI: ${uri}`); const path = match[2].replaceAll('\\', '/'); if (path.split('/').includes('..') || path.startsWith('/')) throw new TypeError('skill URI path escape'); return { bundle: match[1], path }; }
export function skillUri(bundle, path) { return `legion-skill://${bundle}/${path.replaceAll('\\', '/').replace(/^\.\//, '')}`; }
