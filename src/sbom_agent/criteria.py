"""판정 기준은 README 한 곳에만 둔다. 에이전트 지시문과 정답 작성용 표는 여기서 읽어 간다."""
from __future__ import annotations

from pathlib import Path

README = Path(__file__).resolve().parents[2] / "README.md"
START, END = "<!-- criteria:start -->", "<!-- criteria:end -->"


def load_criteria(readme: str | Path = README) -> str:
    text = Path(readme).read_text(encoding="utf-8")
    if START not in text or END not in text:
        raise RuntimeError(f"{readme} 에 판정 기준 구간({START} ~ {END})이 없습니다")
    return text.split(START, 1)[1].split(END, 1)[0].strip()
