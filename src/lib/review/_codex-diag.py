"""Diagnostic — run codex exec with FULL stderr capture (no 500-char truncation).

Use to surface the actual error when the council wrapper just shows a truncated stub.
"""
import subprocess
import sys

def main():
    prompt = "smoke: 1+1 = ?"
    cmd = [r"C:\nvm4w\nodejs\codex.cmd", "exec", "--skip-git-repo-check", "-m", "gpt-5-codex", prompt]
    print(f"[diag] running: {' '.join(cmd[:5])} <prompt-inline>")
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            encoding="utf-8",
            errors="replace",
        )
        print(f"[diag] exit={r.returncode}")
        print(f"[diag] stdout ({len(r.stdout)} chars):")
        print(r.stdout)
        print(f"[diag] stderr ({len(r.stderr)} chars):")
        print(r.stderr)
    except subprocess.TimeoutExpired as e:
        print(f"[diag] timeout after 60s")
        sys.exit(2)
    except Exception as e:
        print(f"[diag] error: {e}")
        sys.exit(3)

if __name__ == "__main__":
    main()
