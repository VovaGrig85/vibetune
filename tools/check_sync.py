#!/usr/bin/env python3
"""
Сверяет код-блоки в audit_prompt.md (источник истины) с их копиями-файлами
для локального прогона. Расхождение = ненулевой код выхода.

Правило проекта: правки вносятся сначала в промт, копия обновляется следом.
Этот скрипт не решает, какая версия правильная - он только говорит, что они
разошлись, и где именно.

Блоки сопоставляются с файлами по порядку появления в промте:
  1-й блок ```python  -> audit_core.py        (Шаг 2, анализатор)
  2-й блок ```python  -> vibetune_payload.py  (Шаг 4, сборка и проверка нагрузки)

vibetune_send.py (send(), ENDPOINT - сетевая часть) в промте не встроен и
этим скриптом не проверяется: он не публикуется и не запускается текущим
потоком промта (см. docs/decisions.md).

Дополнительно проверяет, что контрольная сумма, напечатанная в промте сразу
после кода Шага 2 (её сверяет с собой сам audit_core.py при запуске, кладя
в meta.code_checksum), совпадает с реальной суммой этого код-блока. Иначе
после правки кода легко забыть обновить строку с суммой рядом с ним, и
самопроверка начнёт молча сравнивать не с тем значением.

И ещё одна: metric_version в docs/samples/audit_share.json должен совпадать
с METRIC_VERSION в audit_core.py. Без этой проверки образец формата уже
пролежал протухшим пять версий подряд (metric_version 1 в образце при
реальной метрике 6) - никто не заметил, потому что ничего не заставляло
образец обновляться при правке метрики.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMPT_PATH = ROOT / "audit_prompt.md"
FENCE_OPEN = "```python"
FENCE_CLOSE = "```"

BLOCK_TARGETS = [
    ROOT / "audit_core.py",
    ROOT / "vibetune_payload.py",
]

AUDIT_CORE_PATH = ROOT / "audit_core.py"
SAMPLE_SHARE_PATH = ROOT / "docs" / "samples" / "audit_share.json"
METRIC_VERSION_RE = re.compile(r"^METRIC_VERSION = (\d+)", re.MULTILINE)

CHECKSUM_BLOCK_INDEX = 0  # Шаг 2 (audit_core.py) - тот блок, у которого рядом печатается сумма
CHECKSUM_LINE_RE = re.compile(r"`([0-9a-f]{64})`")


def compute_checksum(text):
    """Та же нормализация, что в audit_core.py: CRLF/CR -> \\n, без конечного
    переноса строки - иначе сумма совпадёт только на одной ОС."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def extract_code_blocks(prompt_text):
    """Возвращает список (block_lines, closing_fence_index) - индекс нужен,
    чтобы найти строку с контрольной суммой сразу после блока."""
    lines = prompt_text.splitlines()
    blocks = []
    i = 0
    while i < len(lines):
        if lines[i].strip() == FENCE_OPEN:
            start = i + 1
            end = None
            for j in range(start, len(lines)):
                if lines[j].strip() == FENCE_CLOSE:
                    end = j
                    break
            if end is None:
                raise SystemExit(f"В {PROMPT_PATH} код-блок, открытый на строке "
                                  f"{i + 1}, не закрыт тройными кавычками")
            blocks.append((lines[start:end], end))
            i = end + 1
        else:
            i += 1
    return blocks


def check_documented_checksum(prompt_lines, block_lines, closing_fence_index):
    """Строка с контрольной суммой ищется в нескольких строках сразу после
    закрывающих кавычек код-блока - там же, где Шаг 2 её печатает человеку."""
    window = prompt_lines[closing_fence_index + 1:closing_fence_index + 8]
    documented = None
    for line in window:
        m = CHECKSUM_LINE_RE.search(line)
        if m:
            documented = m.group(1)
            break
    if documented is None:
        print("РАСХОЖДЕНИЕ [контрольная сумма]: рядом с код-блоком Шага 2 не "
              "найдена строка вида 'SHA-256 ... `<64 hex>`'.")
        return False

    actual = compute_checksum("\n".join(block_lines))
    if documented == actual:
        print(f"OK: контрольная сумма рядом с код-блоком Шага 2 совпадает с "
              f"реальной суммой блока ({actual}).")
        return True

    print("РАСХОЖДЕНИЕ [контрольная сумма]: строка рядом с код-блоком Шага 2 "
          "устарела.")
    print(f"  в промте:  {documented}")
    print(f"  реальная:  {actual}")
    print("  Код-блок правили и забыли пересчитать сумму рядом с ним.")
    return False


def compare(name, block_lines, file_path):
    if not file_path.exists():
        print(f"НЕ НАЙДЕН {file_path}")
        return False
    file_lines = file_path.read_text(encoding="utf-8").splitlines()

    diffs = []
    max_len = max(len(block_lines), len(file_lines))
    for i in range(max_len):
        a = block_lines[i] if i < len(block_lines) else None
        b = file_lines[i] if i < len(file_lines) else None
        if a != b:
            diffs.append(i + 1)

    if not diffs:
        print(f"OK: {name} — код-блок audit_prompt.md ({len(block_lines)} строк) "
              f"совпадает с {file_path.name} построчно.")
        return True

    print(f"РАСХОЖДЕНИЕ [{name}]: {len(diffs)} строк(а/и) не совпадают между "
          f"audit_prompt.md и {file_path.name}.")
    print(f"  audit_prompt.md: {len(block_lines)} строк кода | "
          f"{file_path.name}: {len(file_lines)} строк")
    shown = diffs[:20]
    for ln in shown:
        a = block_lines[ln - 1] if ln - 1 < len(block_lines) else "<нет строки>"
        b = file_lines[ln - 1] if ln - 1 < len(file_lines) else "<нет строки>"
        print(f"  строка {ln}:")
        print(f"    промт: {a!r}")
        print(f"    файл:  {b!r}")
    if len(diffs) > len(shown):
        print(f"  ... и ещё {len(diffs) - len(shown)} строк(и)")
    return False


def check_sample_metric_version():
    """docs/samples/audit_share.json должен показывать ТЕКУЩИЙ metric_version -
    без этой проверки образец формата стареет молча (см. docstring модуля)."""
    if not AUDIT_CORE_PATH.exists():
        print(f"НЕ НАЙДЕН {AUDIT_CORE_PATH}")
        return False
    m = METRIC_VERSION_RE.search(AUDIT_CORE_PATH.read_text(encoding="utf-8"))
    if not m:
        print(f"РАСХОЖДЕНИЕ [metric_version]: не нашёл 'METRIC_VERSION = <число>' "
              f"в {AUDIT_CORE_PATH.name}.")
        return False
    current = int(m.group(1))

    if not SAMPLE_SHARE_PATH.exists():
        print(f"НЕ НАЙДЕН {SAMPLE_SHARE_PATH}")
        return False
    try:
        sample = json.loads(SAMPLE_SHARE_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"РАСХОЖДЕНИЕ [metric_version]: {SAMPLE_SHARE_PATH} не читается "
              f"как JSON: {e}")
        return False
    sample_version = (sample.get("meta") or {}).get("metric_version")
    if sample_version != current:
        print(f"РАСХОЖДЕНИЕ [metric_version]: docs/samples/audit_share.json "
              f"показывает metric_version {sample_version!r}, а в audit_core.py "
              f"сейчас {current}. Образец формата отстал от метрики - обнови "
              f"docs/samples/audit_share.json.")
        return False
    print(f"OK: docs/samples/audit_share.json показывает актуальный "
          f"metric_version ({current}).")
    return True


def main():
    if not PROMPT_PATH.exists():
        print(f"НЕ НАЙДЕН {PROMPT_PATH}")
        return 1

    prompt_text = PROMPT_PATH.read_text(encoding="utf-8")
    blocks = extract_code_blocks(prompt_text)
    if len(blocks) != len(BLOCK_TARGETS):
        print(f"ОЖИДАЛОСЬ {len(BLOCK_TARGETS)} код-блок(а/ов) ```python в "
              f"audit_prompt.md, НАЙДЕНО {len(blocks)}. Список целей в "
              f"check_sync.py (BLOCK_TARGETS) и число блоков в промте разошлись.")
        return 1

    ok = True
    for (block, target) in zip(blocks, BLOCK_TARGETS):
        block_lines, _ = block
        ok = compare(target.name, block_lines, target) and ok

    checksum_block_lines, checksum_fence_index = blocks[CHECKSUM_BLOCK_INDEX]
    prompt_lines = prompt_text.splitlines()
    ok = check_documented_checksum(prompt_lines, checksum_block_lines, checksum_fence_index) and ok

    ok = check_sample_metric_version() and ok

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
