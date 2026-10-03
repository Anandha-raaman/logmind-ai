import os
import time
from pathlib import Path
from typing import Generator, Optional, Tuple


class FileTailCollector:
    """
    Robust local log file tailer tracking file position (offset).
    Handles incremental line reading, partial lines, and file truncation/rotation.
    """

    def __init__(self, file_path: Path):
        self.file_path = Path(file_path).resolve()
        self.last_offset: int = 0
        self.partial_line_buffer: str = ""

    def seek_to_end(self) -> int:
        """Seek file position to current end of file (for starting tail from now)."""
        if self.file_path.exists():
            self.last_offset = self.file_path.stat().st_size
        return self.last_offset

    def seek_to_beginning(self) -> int:
        """Reset offset to 0 to process entire file from start."""
        self.last_offset = 0
        self.partial_line_buffer = ""
        return 0

    def collect_new_lines(self) -> Generator[str, None, None]:
        """
        Check for newly appended content, read complete lines, and yield them.
        Buffers incomplete lines until a trailing newline is received.
        """
        if not self.file_path.exists():
            return

        current_size = self.file_path.stat().st_size

        # Handle file truncation (e.g. log file was cleared or rotated)
        if current_size < self.last_offset:
            self.last_offset = 0
            self.partial_line_buffer = ""

        if current_size == self.last_offset:
            return

        with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(self.last_offset)
            chunk = f.read(current_size - self.last_offset)
            self.last_offset = f.tell()

        if not chunk:
            return

        # Combine with any previous partial line buffer
        full_text = self.partial_line_buffer + chunk
        lines = full_text.splitlines(keepends=True)

        # If the last item doesn't end with a newline, buffer it
        if lines and not lines[-1].endswith(('\n', '\r')):
            self.partial_line_buffer = lines.pop()
        else:
            self.partial_line_buffer = ""

        for line in lines:
            stripped = line.rstrip('\r\n')
            if stripped:
                yield stripped
