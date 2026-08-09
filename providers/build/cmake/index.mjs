// CMake build provider: presets/build dirs discovery; never generates implicit
// build configuration.

export function cmakePresetReceipt({ root, presetPresent, presetName, buildDir }) {
  return {
    schemaVersion: 1,
    kind: 'legion-cmake-preset',
    root,
    presetPresent: Boolean(presetPresent),
    presetName: presetName ?? null,
    buildDir: buildDir ?? null,
  };
}

export function cmakeCommand({ root, preset, buildDir = 'build', targets = [] }) {
  const args = preset
    ? ['--preset', preset]
    : ['-S', root, '-B', buildDir];
  if (targets.length) args.push('--target', ...targets);
  return { executable: 'cmake', args, cwd: root, timeoutMs: 300000, environmentKeys: ['PATH', 'HOME', 'CC', 'CXX'] };
}
