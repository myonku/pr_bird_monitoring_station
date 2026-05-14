from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

import main as edge_main


class EdgeMainEntrypointTests(unittest.TestCase):
    def test_run_handles_keyboard_interrupt_gracefully(self) -> None:
        original_main = edge_main.main

        def _raise_keyboard_interrupt() -> None:
            raise KeyboardInterrupt

        edge_main.main = _raise_keyboard_interrupt
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                edge_main.run()
        finally:
            edge_main.main = original_main

        self.assertIn("edge pipeline interrupted by ctrl+c, exiting", buffer.getvalue())
