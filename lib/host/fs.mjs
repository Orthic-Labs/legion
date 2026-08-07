export function filesystemHost(fs) { if (!fs?.readFile) throw new Error('host filesystem requires readFile'); return fs; }
