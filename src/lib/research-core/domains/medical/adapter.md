# Medical engine adapter

This adapter is internal to Research. It does not define a `/doctor` skill and never instructs the
router to bypass Research.

- Anonymous route: call `Health/medical-research-system/doctor.py` without loading patient history.
- Personal the operator route: only after `confirm-personal-medical-route`, pass the canonical
  `Health/medical-research-system/history/operator.yaml` path.
- Preserve the medical engine's PICO, red-flag, citation-verification, privacy, and output-lint gates.
- Return the engine evidence pack to Research Core for shared ledger, contradiction, citecheck, and
  receipt handling.
