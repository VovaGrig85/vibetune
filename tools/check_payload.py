#!/usr/bin/env python3
"""
Прогоняет vibetune_payload.py::prepare() на эталонном audit_share.json
(docs/samples/audit_share.json) и на живом audit_share.json в корне репозитория,
если он там лежит. Падает, если сборка нагрузки не проходит собственную
проверку find_suspicious/check_meta.

Эталонный образец не меняется никогда, поэтому сам по себе не ловит регрессии
в новых полях, которые появляются позже, только в живом отчёте. Живой файл
необязателен: на чистой машине без единого прогона его просто нет, и это не
повод падать.

Это регресс-тест на баг, который уже случался: эвристика на путь/адрес
ловила заодно и обязательные ISO-даты отчёта, из-за чего prepare() отказывал
на каждом без исключения прогоне. Любое новое поле в audit_share.json должно
проходить эту же проверку, прежде чем окажется в промте.

Правило для этого файла (см. docs/decisions.md): каждое новое правило в
find_suspicious добавляется сразу с ДВУМЯ тестами - что запрещённое значение
ловится (check_hash_pattern_is_caught) и что настоящий payload с реальными
обязательными полями проходит без замечаний (check_real_ids_pass). Слишком
широкое правило в этой функции уже дважды ломало отправку у всех подряд:
двоеточие с проверкой длины блокировало обычные даты, символ "собаки" — имя
пакета. SESSION_HASH_RE при добавлении был проверен на install_id/code_checksum
и ложных срабатываний не дал (границы hex-последовательности этому не дают
случиться), но именно такую проверку в первый раз никто не формализовал -
check_real_ids_pass существует, чтобы это никогда больше не было устным
рассуждением при правке regex.
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import copy
import json
from vibetune_payload import prepare  # noqa: E402

SAMPLE_PATH = ROOT / "docs" / "samples" / "audit_share.json"
LIVE_PATH = ROOT / "audit_share.json"


def check_file(path, required):
    label = path.relative_to(ROOT)
    if not path.exists():
        if required:
            print(f"НЕ НАЙДЕН {path}")
            return False
        print(f"ПРОПУЩЕНО: {label} не найден рядом (это не ошибка).")
        return True

    share = json.loads(path.read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory() as tmp:
        out_path, problems = prepare(share, tmp)

    if problems:
        print(f"ПРОВАЛ: prepare() на {label} вернул {len(problems)} "
              f"замечани(е/й) — нагрузка не прошла бы собственную проверку:")
        for p in problems:
            print(" ", p)
        return False

    if not out_path:
        print(f"ПРОВАЛ: prepare() на {label} не вернул путь к payload, хотя problems пуст.")
        return False

    print(f"OK: {label} проходит prepare() без замечаний.")
    return True


def check_hash_pattern_is_caught():
    """Регресс-тест на баг, который уже случался: session_prefix (и то, что из
    него собрано, вроде episode_ref) исключается из share по ИМЕНИ поля
    (strip_ids) - если однажды кто-то заведёт новое поле с таким же по форме
    значением и забудет вписать его в белый список, утечка уйдёт молча.
    find_suspicious теперь ловит восемь подряд hex-символов по ФОРМЕ, а не по
    имени - здесь проверяем, что это действительно работает, а не просто
    существует в коде."""
    if not SAMPLE_PATH.exists():
        print(f"НЕ НАЙДЕН {SAMPLE_PATH}")
        return False
    share = copy.deepcopy(json.loads(SAMPLE_PATH.read_text(encoding="utf-8")))
    # Форма настоящей утечки: хеш сессии + локальные дата и время (episode_ref),
    # под ПРОИЗВОЛЬНЫМ именем поля - имя не должно иметь значения для проверки.
    share["some_new_field_nobody_whitelisted_yet"] = "89b376d9 29.08 15:27"

    with tempfile.TemporaryDirectory() as tmp:
        out_path, problems = prepare(share, tmp)

    if not problems:
        print("ПРОВАЛ [шаблон хеша]: prepare() пропустил восьмисимвольный "
              "hex-фрагмент под незнакомым именем поля - защита по форме не "
              "работает.")
        return False
    if out_path:
        print("ПРОВАЛ [шаблон хеша]: prepare() вернул путь к payload, хотя "
              "problems не пуст - это не должно быть возможно одновременно.")
        return False
    if problems[0][0] != "_warning" or not problems[0][1]:
        print("ПРОВАЛ [шаблон хеша]: первой записью в problems при отказе "
              "должно идти предупреждение (LEAK_CHECK_WARNING) - агент читает "
              "именно то, что вернул prepare(), в момент отказа, не промт.")
        return False
    real_problems = [p for p in problems if p[0] != "_warning"]
    print(f"OK: восьмисимвольный hex-фрагмент под новым именем поля пойман "
          f"({real_problems[0][0]}), предупреждение против подгонки данных "
          f"идёт первой записью.")
    return True


def check_real_ids_pass():
    """Парный тест к check_hash_pattern_is_caught(): SESSION_HASH_RE ищет
    восемь hex-символов, не примыкающих к другим hex-символам, - настоящие
    install_id (16 hex подряд) и code_checksum (64 hex подряд) устроены так,
    что ЛЮБОЕ восьмисимвольное окно внутри них с одной из сторон граничит с
    ещё одним hex-символом, и правило не должно в них сработать. Без этого
    теста легко сузить или расширить regex и не заметить, что он начал ловить
    собственные обязательные поля - см. правило в docs/decisions.md: каждое
    новое правило в find_suspicious добавляется вместе с обоими тестами
    сразу, а не только с тем, что ловит плохое значение."""
    if not SAMPLE_PATH.exists():
        print(f"НЕ НАЙДЕН {SAMPLE_PATH}")
        return False
    share = copy.deepcopy(json.loads(SAMPLE_PATH.read_text(encoding="utf-8")))
    share["meta"]["install_id"] = "0123456789abcdef"
    share["meta"]["code_checksum"] = (
        "d452510cb7e80a44b9986bd3de9aff159c5f331bebec7982d10250cf673bf9dd")

    with tempfile.TemporaryDirectory() as tmp:
        out_path, problems = prepare(share, tmp)

    if problems:
        print(f"ПРОВАЛ [настоящие id проходят]: install_id (16 hex) и "
              f"code_checksum (64 hex) настоящей формы не должны ловиться "
              f"проверкой утечек, а prepare() вернул: {problems}")
        return False
    if not out_path:
        print("ПРОВАЛ [настоящие id проходят]: prepare() не вернул путь к "
              "payload, хотя problems пуст.")
        return False
    print("OK: настоящие install_id (16 hex) и code_checksum (64 hex) "
          "проходят prepare() без замечаний.")
    return True


def check_long_text_allowlist():
    """Регресс-тест на находку из живого прогона на Claude Code: честное
    описание гранулярности шага не влезало в общий потолок в 120 символов, и
    харнесс подрезал его вручную, лишь бы проверка прошла — подогнал данные
    под проверку, а не под правду (см. docs/decisions.md). Решение —
    не общий потолок, а именной список путей (LONG_TEXT_ALLOWED_PATHS в
    vibetune_payload.py) с более высоким, но всё ещё проверяемым потолком. Три
    условия сразу: длинное честное описание на разрешённом пути проходит;
    путь/утечка на ТОМ ЖЕ разрешённом пути всё равно ловится (ослабили
    только длину, не остальные проверки); та же длинная строка на ЛЮБОМ
    другом пути по-прежнему ловится (потолок не поднят всем полям сразу)."""
    if not SAMPLE_PATH.exists():
        print(f"НЕ НАЙДЕН {SAMPLE_PATH}")
        return False
    base = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))

    honest_long = ("Каждая строка лога соответствует одному сообщению в блоке "
                   "разговора, который может включать рассуждения модели, "
                   "один или несколько вызовов инструментов и их результаты")
    if not (120 < len(honest_long) <= 300):
        print(f"ПРОВАЛ [длинные поля]: тестовая строка вне диапазона теста "
              f"({len(honest_long)} символов) — поправь фикстуру.")
        return False

    ok = True

    share = copy.deepcopy(base)
    share["environment"]["step_granularity_note"] = honest_long
    with tempfile.TemporaryDirectory() as tmp:
        _out, problems = prepare(share, tmp)
    if problems:
        print(f"ПРОВАЛ [длинные поля]: честное описание гранулярности "
              f"({len(honest_long)} симв.) не должно ловиться на разрешённом "
              f"пути, а prepare() вернул: {problems}")
        ok = False

    share2 = copy.deepcopy(base)
    share2["environment"]["step_granularity_note"] = "C:/Users/x/project/" + "a" * 110
    with tempfile.TemporaryDirectory() as tmp:
        _out, problems2 = prepare(share2, tmp)
    if not problems2:
        print("ПРОВАЛ [длинные поля]: путь на РАЗРЕШЁННОМ по длине поле всё "
              "равно должен ловиться — ослаблена только длина, не остальные "
              "проверки.")
        ok = False

    share3 = copy.deepcopy(base)
    share3["some_other_field_not_on_the_allowlist"] = honest_long
    with tempfile.TemporaryDirectory() as tmp:
        _out, problems3 = prepare(share3, tmp)
    if not problems3:
        print("ПРОВАЛ [длинные поля]: та же длинная строка на ЛЮБОМ ДРУГОМ "
              "пути должна ловиться потолком в 120 символов — иначе потолок "
              "ослаблен для всех полей, а не только для перечисленных.")
        ok = False

    if ok:
        print(f"OK: длинный текст ({len(honest_long)} симв.) на "
              f"environment.step_granularity_note проходит, а путь на том же "
              f"поле и та же длина на любом другом поле по-прежнему ловятся.")
    return ok


def main():
    ok_sample = check_file(SAMPLE_PATH, required=True)
    ok_live = check_file(LIVE_PATH, required=False)
    ok_pattern = check_hash_pattern_is_caught()
    ok_real_ids = check_real_ids_pass()
    ok_long_text = check_long_text_allowlist()
    return 0 if (ok_sample and ok_live and ok_pattern and ok_real_ids and ok_long_text) else 1


if __name__ == "__main__":
    sys.exit(main())
