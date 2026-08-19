# Medical engine adapter

This adapter is internal to Research. It does not define a `/doctor` skill and never instructs the
router to bypass Research.

- Anonymous route: call `<medical-engine-root>/doctor.py` without loading patient history.
- Personal route: only after `confirm-personal-medical-route`, pass the host-supplied
  configured patient-history file path (never a hardcoded path in this package).
- Preserve the medical engine's PICO, red-flag, citation-verification, privacy, and output-lint gates.
- Return the engine evidence pack to Research Core for shared ledger, contradiction, citecheck, and
  receipt handling.
