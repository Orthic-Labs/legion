import { loadRepositoryConfig, loadUserConfig } from './index.mjs';
export function loadConfig({ root, userConfigPath, defaults, cli }) { return { user: loadUserConfig(userConfigPath), repository: loadRepositoryConfig(root), defaults, cli }; }
