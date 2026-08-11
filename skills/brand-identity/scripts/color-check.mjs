#!/usr/bin/env node
// color-check.mjs — zero-dependency color math for the brand-identity Color Science gate.
// WCAG 2.2 contrast ratios and OKLCH↔sRGB conversion, computed from the standard formulas so the
// agent NEVER reports a contrast grade or an OKLCH value from memory (eyeballed darkening routinely
// lands at ~4.1–4.3 and silently fails AA). No external library — sRGB/OKLab matrices are inlined.
//
// Usage:
//   node color-check.mjs contrast <fg-hex> <bg-hex>            # ratio + AA/AAA verdict
//   node color-check.mjs oklch <hex>                           # sRGB hex -> OKLCH (L C H)
//   node color-check.mjs oklch-to-hex <L> <C> <H>              # OKLCH -> nearest in-gamut sRGB hex
//   node color-check.mjs audit '<json>'                        # [{name,fg,bg,min?}] -> pass/fail table (JSON)
//
// Exit code is nonzero when an `audit` run has ANY failing pair, so a caller can fail-closed.

// ---------- sRGB helpers ----------
function hexToRgb(hex) {
  const h = String(hex).trim().replace(/^#/, '');
  const s = h.length === 3 ? h.split('').map(c => c + c).join('') : h;
  if (!/^[0-9a-fA-F]{6}$/.test(s)) throw new Error(`bad hex: ${hex}`);
  return [parseInt(s.slice(0, 2), 16), parseInt(s.slice(2, 4), 16), parseInt(s.slice(4, 6), 16)];
}
function rgbToHex(r, g, b) {
  const c = (n) => Math.max(0, Math.min(255, Math.round(n))).toString(16).padStart(2, '0');
  return `#${c(r)}${c(g)}${c(b)}`;
}
const srgbToLinear = (c) => { const x = c / 255; return x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; };
const linearToSrgb = (x) => { const c = x <= 0.0031308 ? x * 12.92 : 1.055 * (x ** (1 / 2.4)) - 0.055; return c * 255; };

// ---------- WCAG relative luminance + contrast ----------
function relLuminance([r, g, b]) {
  const [R, G, B] = [r, g, b].map(srgbToLinear);
  return 0.2126 * R + 0.7152 * G + 0.0722 * B;
}
function contrastRatio(fgHex, bgHex) {
  const L1 = relLuminance(hexToRgb(fgHex));
  const L2 = relLuminance(hexToRgb(bgHex));
  const [hi, lo] = L1 >= L2 ? [L1, L2] : [L2, L1];
  return (hi + 0.05) / (lo + 0.05);
}

// ---------- OKLCH ↔ sRGB (Björn Ottosson OKLab, CSS Color 4) ----------
function srgbToOklch(hex) {
  const [r, g, b] = hexToRgb(hex).map(srgbToLinear);
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  const L = 0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s;
  const A = 1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s;
  const B = 0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s;
  const C = Math.hypot(A, B);
  let H = Math.atan2(B, A) * 180 / Math.PI;
  if (H < 0) H += 360;
  return { L, C, H };
}
function oklchToRgb(L, C, H) {
  const a = C * Math.cos(H * Math.PI / 180);
  const b = C * Math.sin(H * Math.PI / 180);
  const l_ = L + 0.3963377774 * a + 0.2158037573 * b;
  const m_ = L - 0.1055613458 * a - 0.0638541728 * b;
  const s_ = L - 0.0894841775 * a - 1.2914855480 * b;
  const l = l_ ** 3, m = m_ ** 3, s = s_ ** 3;
  const r = +4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s;
  const g = -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s;
  const bl = -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s;
  const clamped = [r, g, bl].some(v => v < -0.001 || v > 1.001);
  return { hex: rgbToHex(linearToSrgb(r), linearToSrgb(g), linearToSrgb(bl)), inGamut: !clamped };
}

// ---------- CLI ----------
const [cmd, ...rest] = process.argv.slice(2);
const round = (n, d = 2) => Math.round(n * 10 ** d) / 10 ** d;
try {
  if (cmd === 'contrast') {
    const [fg, bg] = rest;
    const ratio = contrastRatio(fg, bg);
    console.log(JSON.stringify({
      fg, bg, ratio: round(ratio),
      AA_normal: ratio >= 4.5, AA_large_or_ui: ratio >= 3, AAA_normal: ratio >= 7,
    }, null, 2));
  } else if (cmd === 'oklch') {
    const { L, C, H } = srgbToOklch(rest[0]);
    console.log(JSON.stringify({ hex: rest[0], L: round(L, 4), C: round(C, 4), H: round(H, 2) }, null, 2));
  } else if (cmd === 'oklch-to-hex') {
    const [L, C, H] = rest.map(Number);
    console.log(JSON.stringify({ L, C, H, ...oklchToRgb(L, C, H) }, null, 2));
  } else if (cmd === 'audit') {
    const pairs = JSON.parse(rest[0]);
    const rows = pairs.map((p) => {
      const ratio = contrastRatio(p.fg, p.bg);
      const min = p.min ?? 4.5;
      return { name: p.name ?? `${p.fg}/${p.bg}`, fg: p.fg, bg: p.bg, ratio: round(ratio), min, pass: ratio >= min };
    });
    console.log(JSON.stringify({ rows, allPass: rows.every(r => r.pass) }, null, 2));
    if (!rows.every(r => r.pass)) process.exit(1);
  } else {
    console.error('usage: contrast <fg> <bg> | oklch <hex> | oklch-to-hex <L> <C> <H> | audit \'<json>\'');
    process.exit(2);
  }
} catch (e) {
  console.error(`error: ${e.message}`);
  process.exit(2);
}
