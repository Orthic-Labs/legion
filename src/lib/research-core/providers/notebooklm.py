#!/usr/bin/env python3
"""NotebookLM provider/operation adapter.

NotebookLM answers remain leads. Only underlying source URLs that are separately
opened and passage-located can be converted into evidence records.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any


class NotebookLMAdapter:
    name = 'notebooklm'

    def __init__(self, executable: str = 'notebooklm'):
        resolved = shutil.which(executable)
        if not resolved:
            raise RuntimeError('notebooklm CLI is not installed')
        self.executable = resolved

    def _run(self, args: list[str], timeout: int = 180) -> Any:
        proc = subprocess.run([self.executable, *args], capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or f'notebooklm exited {proc.returncode}')
        text = proc.stdout.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {'text': text}

    def status(self) -> Any:
        return self._run(['status'])

    def list_notebooks(self) -> Any:
        return self._run(['list', '--json'])

    def ask(self, notebook_id: str, question: str) -> dict[str, Any]:
        result = self._run(['ask', question, '--notebook', notebook_id, '--json'])
        return {'evidence_status': 'lead', 'provider': self.name, 'answer': result}

    def create(self, title: str) -> Any:
        return self._run(['create', title, '--json'])

    def add_source(self, notebook_id: str, source: str) -> Any:
        return self._run(['source', 'add', source, '--notebook', notebook_id, '--json'])

    def generate(self, notebook_id: str, artifact_type: str, instructions: str | None = None) -> Any:
        args = ['generate', artifact_type]
        if instructions:
            args.append(instructions)
        args += ['--notebook', notebook_id, '--json']
        return self._run(args, timeout=600)
