import { createHash } from "node:crypto";

export const RELEASE_CAPTURE_MAX_BYTES = 64 * 1024 * 1024;
export const RELEASE_COMMAND_TIMEOUT_MS = 30 * 60 * 1000;
export const INSTALLED_COMMAND_TIMEOUT_MS = 5 * 60 * 1000;

const DIAGNOSTIC_LIMIT = 4096;

function text(value) {
	return String(value ?? "").trim();
}

function clipped(value) {
	const normalized = text(value);
	if (normalized.length <= DIAGNOSTIC_LIMIT) return normalized;
	return `${normalized.slice(0, DIAGNOSTIC_LIMIT)}… [truncated ${normalized.length - DIAGNOSTIC_LIMIT} chars]`;
}

export function releaseSpawnOptions(options = {}, timeout = RELEASE_COMMAND_TIMEOUT_MS) {
	return {
		...options,
		encoding: options.encoding ?? "utf8",
		windowsHide: options.windowsHide ?? true,
		maxBuffer: RELEASE_CAPTURE_MAX_BYTES,
		timeout,
	};
}

export function commandDiagnostic(result) {
	const parts = [];
	const error = clipped(result?.error?.message);
	if (error) parts.push(`error=${error}`);
	if (result?.status !== undefined && result?.status !== null) parts.push(`exit=${result.status}`);
	if (result?.signal) parts.push(`signal=${result.signal}`);
	const stderr = clipped(result?.stderr);
	const stdout = clipped(result?.stdout);
	if (stderr) parts.push(`stderr=${stderr}`);
	if (stdout) parts.push(`stdout=${stdout}`);
	return parts.join("; ") || "command returned no diagnostic output";
}

function streamEvidence(value) {
	const output = String(value ?? "");
	const bytes = Buffer.byteLength(output);
	return {
		bytes,
		sha256: createHash("sha256").update(output).digest("hex"),
	};
}

export function commandEvidence(result) {
	return {
		exitCode: Number.isInteger(result?.status) ? result.status : null,
		signal: result?.signal ?? null,
		stdout: streamEvidence(result?.stdout),
		stderr: streamEvidence(result?.stderr),
	};
}
