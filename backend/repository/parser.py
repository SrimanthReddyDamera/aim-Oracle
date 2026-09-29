"""
Structured Error & Stack Trace Parser (ORACLE 5.0 - Step 4)

Extracts structured, normalized failure representations from raw error logs
and tracebacks across runtimes (Python, Node/TypeScript, Go, generic).
"""

from __future__ import annotations

import re
from typing import List, Optional
from pydantic import BaseModel, Field


class StackFrame(BaseModel):
    """Normalized representation of an individual execution stack frame."""
    file: str
    line: int
    column: Optional[int] = None
    function: Optional[str] = None
    code_context: Optional[str] = None
    raw_text: str = ""


class NormalizedError(BaseModel):
    """Normalized structured error representation."""
    exception_type: str
    message: str
    runtime: str = "python"
    frames: List[StackFrame] = Field(default_factory=list)
    root_frame: Optional[StackFrame] = None
    raw_trace: str = ""


class StackTraceParser:
    """
    Robust multi-runtime error and stack trace parser.
    Extracts exception type, message, and ordered stack frames.
    """

    # Python traceback patterns
    PYTHON_FRAME_RE = re.compile(
        r'File\s+["\'](?P<file>[^"\']+)["\'],\s+line\s+(?P<line>\d+)(?:,\s+in\s+(?P<func>[^\n]+))?'
    )
    PYTHON_EXC_RE = re.compile(
        r'^(?P<type>[A-Za-z_][A-Za-z0-9_\.]*(?:Error|Exception|Panic|Fault)?):\s*(?P<msg>.*)$',
        re.MULTILINE
    )

    # Node/TypeScript stack frame pattern: "at Object.<anonymous> (/app/src/index.ts:42:15)"
    NODE_FRAME_RE = re.compile(
        r'^\s*at\s+(?:(?P<func>[^\(\s]+)\s+)?\(?(?P<file>[^\:\)\s]+):(?P<line>\d+):(?P<col>\d+)\)?',
        re.MULTILINE
    )

    # Go panic pattern: "main.go:42 +0x3a"
    GO_FRAME_RE = re.compile(
        r'^\s*(?P<file>[^\:\s]+\.go):(?P<line>\d+)(?:\s+\+0x[0-9a-f]+)?',
        re.MULTILINE
    )

    # Generic log pattern: "payment_service.py:184: ..."
    GENERIC_LINE_RE = re.compile(
        r'(?P<file>[a-zA-Z0-9_\-\.\/\\~]+\.[a-zA-Z0-9]+):(?P<line>\d+)(?::(?P<col>\d+))?'
    )

    @classmethod
    def parse(cls, raw_error: str) -> NormalizedError:
        if not raw_error or not raw_error.strip():
            return NormalizedError(
                exception_type="UnknownError",
                message="No error text provided",
                runtime="unknown",
                raw_trace=raw_error or "",
            )

        text = raw_error.strip()

        # Try Python parsing first
        if "Traceback (most recent call last):" in text or ".py" in text:
            parsed = cls._parse_python(text)
            if parsed.frames:
                return parsed

        # Try Node/JS parsing
        if "at " in text and (":\\" in text or "/" in text or ".ts" in text or ".js" in text):
            parsed = cls._parse_node(text)
            if parsed.frames:
                return parsed

        # Try Go parsing
        if "panic:" in text or ".go:" in text:
            parsed = cls._parse_go(text)
            if parsed.frames:
                return parsed

        # Fallback to generic line scanner
        return cls._parse_generic(text)

    @classmethod
    def _parse_python(cls, text: str) -> NormalizedError:
        frames: List[StackFrame] = []
        lines = text.split("\n")

        for idx, line in enumerate(lines):
            m = cls.PYTHON_FRAME_RE.search(line)
            if m:
                file_path = m.group("file").replace("\\", "/")
                # Strip absolute workspace prefixes if present
                file_clean = cls._clean_file_path(file_path)
                line_num = int(m.group("line"))
                func = m.group("func")
                if func:
                    func = func.strip()

                # Next line often contains code context
                code_ctx = None
                if idx + 1 < len(lines) and not lines[idx + 1].strip().startswith("File "):
                    code_ctx = lines[idx + 1].strip()

                frames.append(
                    StackFrame(
                        file=file_clean,
                        line=line_num,
                        function=func,
                        code_context=code_ctx,
                        raw_text=line.strip(),
                    )
                )

        # Extract exception type and message from last matching exception line
        exc_matches = list(cls.PYTHON_EXC_RE.finditer(text))
        if exc_matches:
            last_m = exc_matches[-1]
            exc_type = last_m.group("type").strip()
            exc_msg = last_m.group("msg").strip()
        else:
            # Fallback: look at the last non-empty line
            last_line = [l.strip() for l in lines if l.strip()][-1]
            if ":" in last_line:
                parts = last_line.split(":", 1)
                exc_type = parts[0].strip()
                exc_msg = parts[1].strip()
            else:
                exc_type = "RuntimeError"
                exc_msg = last_line

        root = frames[-1] if frames else None
        return NormalizedError(
            exception_type=exc_type,
            message=exc_msg,
            runtime="python",
            frames=frames,
            root_frame=root,
            raw_trace=text,
        )

    @classmethod
    def _parse_node(cls, text: str) -> NormalizedError:
        frames: List[StackFrame] = []
        for m in cls.NODE_FRAME_RE.finditer(text):
            file_clean = cls._clean_file_path(m.group("file").replace("\\", "/"))
            frames.append(
                StackFrame(
                    file=file_clean,
                    line=int(m.group("line")),
                    column=int(m.group("col")),
                    function=m.group("func") or "anonymous",
                    raw_text=m.group(0).strip(),
                )
            )

        # First line usually contains "TypeError: msg"
        first_line = text.split("\n")[0].strip()
        if ":" in first_line:
            parts = first_line.split(":", 1)
            exc_type = parts[0].strip()
            exc_msg = parts[1].strip()
        else:
            exc_type = "Error"
            exc_msg = first_line

        root = frames[0] if frames else None
        return NormalizedError(
            exception_type=exc_type,
            message=exc_msg,
            runtime="node",
            frames=frames,
            root_frame=root,
            raw_trace=text,
        )

    @classmethod
    def _parse_go(cls, text: str) -> NormalizedError:
        frames: List[StackFrame] = []
        for m in cls.GO_FRAME_RE.finditer(text):
            file_clean = cls._clean_file_path(m.group("file").replace("\\", "/"))
            frames.append(
                StackFrame(
                    file=file_clean,
                    line=int(m.group("line")),
                    function="unknown",
                    raw_text=m.group(0).strip(),
                )
            )

        exc_type = "Panic"
        exc_msg = "Go runtime panic"
        for line in text.split("\n"):
            if line.startswith("panic:"):
                exc_msg = line[6:].strip()
                break

        root = frames[0] if frames else None
        return NormalizedError(
            exception_type=exc_type,
            message=exc_msg,
            runtime="go",
            frames=frames,
            root_frame=root,
            raw_trace=text,
        )

    @classmethod
    def _parse_generic(cls, text: str) -> NormalizedError:
        frames: List[StackFrame] = []
        for m in cls.GENERIC_LINE_RE.finditer(text):
            file_path = m.group("file")
            # Only consider files with source code extensions
            if any(file_path.endswith(ext) for ext in [".py", ".ts", ".js", ".go", ".java", ".rs"]):
                file_clean = cls._clean_file_path(file_path.replace("\\", "/"))
                col = int(m.group("col")) if m.group("col") else None
                frames.append(
                    StackFrame(
                        file=file_clean,
                        line=int(m.group("line")),
                        column=col,
                        function="unknown",
                        raw_text=m.group(0),
                    )
                )

        first_line = text.split("\n")[0].strip()
        if ":" in first_line:
            parts = first_line.split(":", 1)
            exc_type = parts[0].strip()
            exc_msg = parts[1].strip()
        else:
            exc_type = "IncidentError"
            exc_msg = first_line[:120]

        root = frames[-1] if frames else None
        return NormalizedError(
            exception_type=exc_type,
            message=exc_msg,
            runtime="generic",
            frames=frames,
            root_frame=root,
            raw_trace=text,
        )

    @staticmethod
    def _clean_file_path(path_str: str) -> str:
        """Strip host-specific absolute paths to yield normalized repository-relative paths."""
        p = path_str.replace("\\", "/")
        # Common project marker anchors
        for anchor in ["/src/", "/app/", "/tests/", "/test/", "/lib/", "/pkg/", "/backend/"]:
            if anchor in p:
                idx = p.find(anchor)
                return p[idx + 1:]  # Return path starting with "src/..."

        # If already relative
        if not p.startswith("/") and not (len(p) > 1 and p[1] == ":"):
            return p

        # Fallback to filename
        return p.split("/")[-1]
