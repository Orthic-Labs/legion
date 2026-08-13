# Effect classification

Classify in fixed order: valid explicit declared door, capability category, semantic risk, then fail-safe default. `FILE_WRITE`/`FILE_MOVE` are reversible; `FILE_DELETE`/`VCS_PUSH`/`PUBLISH`/`EXTERNAL_SIDE_EFFECT` are one-way; `CREDENTIAL_ACCESS`/`DEPENDENCY_INSTALL`/`VCS_COMMIT` are authority-sensitive. Command, network, & process effects continue to semantic risk. Destructive, irreversible, data-loss, or external-commitment risk is one-way; authority, credential, trust-boundary, production, spend, send, or publish risk is authority-sensitive. Unresolved input is authority-sensitive with `safe_default` basis.

Persist declared type, matched rule, basis, & door. Preferences, rehydrated material, & caller claims cannot downgrade a door.
