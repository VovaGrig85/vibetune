#!/usr/bin/env python3
"""
AI Workspace Audit - CORE (v2.0.0-community)
Фиксированная логика анализа. Пути и схему логов НЕ ищет - берёт из
audit_discovery.json, который заполняет сам харнесс.
Локально, без сети, без сторонних библиотек.
"""

import hashlib
import json
import os
import platform
import re
import secrets
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

TOOL_VERSION = "3.10"
SCHEMA_VERSION = 10
METRIC_VERSION = 12
METRIC_CHANGES = "служебные строки лога не считаются шагами агента; без описания типов строк — шаги не измерены"
# Короткий заголовок, не абзац - подробности по каждой версии метрики идут в
# docs/CHANGELOG.md, сюда только то, что не встанет в один диагноз.
METRIC_CHANGES_MAX_LEN = 120  # тот же порог, что в find_suspicious (vibetune_payload.py,
                               # Шаг 4) - проверяем здесь же, при запуске, а не ждём
                               # записи payload, чтобы отчёт с длинным заголовком не собрался.
if len(METRIC_CHANGES) > METRIC_CHANGES_MAX_LEN:
    raise ValueError(f"METRIC_CHANGES длиннее {METRIC_CHANGES_MAX_LEN} символов "
                      f"({len(METRIC_CHANGES)}) - подробности переносить в "
                      f"docs/CHANGELOG.md, здесь оставлять только заголовок.")
# Не сливать в одну строку.
AUDIT_MARKER = "AGENT_WORKSPACE" + "_AUDIT_V2"

INACTIVITY_SPLIT_MIN = 45.0
HARD_SPLIT_MIN = 180.0
SHORT_MSG_LIMIT = 85
MIN_USER_TURNS = 2            # эпизоды короче не считаем
MIN_STEPS_FOR_INVISIBLE = 50  # минимум шагов агента, чтобы эпизод считался автономным
USER_MSG_CAP = 400            # до скольких символов обрезать реплику в локальной выгрузке
INVISIBLE_RATIO_FACTOR = 2.0  # во сколько раз выше своей же медианы должно быть
                              # число действий на реплику, чтобы попасть в список

# Проверка правдоподобия распределения ролей.
ROLE_SHARE_REFERENCE = 0.03
ROLE_SHARE_SUSPICIOUS = 0.25
ROLE_STEPS_PER_TURN_REFERENCE = 30.0
ROLE_STEPS_PER_TURN_SUSPICIOUS = 3.0
ROLE_PLAUSIBILITY_MIN_EVENTS = 30   # на совсем маленькой выборке проверка только шумит

MIN_EPISODES_PER_GROUP = 3  # меньше — медиану по виду работы не публикуем, а не выдумываем

EDIT_TOOL_HINTS = ("write", "edit", "replace", "patch", "create_file", "str_replace")

# Имя инструмента и признак его отказа часто лежат на РАЗНЫХ строках лога:
# строка-вызов объявляет инструмент, строка-результат несёт статус без имени.
# Без id-поля связи (field_map.tool_call_id / tool_result_ref_id) единственный
# способ связать их - взять ближайший предыдущий вызов в той же сессии. Дальше
# этого окна (в строках лога, не по времени) считаем, что связи уже нет, а не
# тянем к первому попавшемуся вызову через всю сессию.
MAX_TOOL_LINK_GAP = 40

# Окно поиска обхода (detect_workaround_chains) ограничено строками лога тем же
# MAX_TOOL_LINK_GAP, но одних строк мало: если между соседними событиями цепочки
# прошло больше нескольких минут, это уже не "агент тут же попробовал иначе", а
# два не связанных между собой действия, разделённых паузой (агент отвлёкся,
# ждал долгий процесс). Порог - минуты между СОСЕДНИМИ событиями цепочки, не
# суммарная длительность всей цепочки.
WORKAROUND_MAX_GAP_MINUTES = 5.0

# Куда разные харнессы кладут аргументы инструмента и путь к файлу внутри них.
# Используется как запасной вариант, если field_map не подошёл к конкретной записи.
ARG_CONTAINERS = ("tool_calls", "toolCalls", "tool_call", "tool_use", "function_call",
                  "tool_args", "input", "parameters", "args", "arguments", "params")
FILE_ARG_KEYS = ("path", "file_path", "filePath", "target_file", "targetFile",
                 "file", "filename", "fileName", "uri", "notebook_path")
TOOL_NAME_KEYS = ("tool_name", "toolName", "tool", "name", "function")
MCP_SERVER_KEYS = ("ServerName", "server_name", "serverName", "server", "mcp_server")

# Признак ошибки бывает булевым, а бывает строковым статусом. Строки трактуем
# только по явным спискам: неизвестное значение НЕ считается ошибкой, но
# попадает в диагностику, чтобы дефект был виден, а не портил метрики молча.
ERROR_TRUE = {"true", "1", "error", "errored", "failed", "failure", "fail",
              "aborted", "cancelled", "canceled", "timeout", "timed_out",
              "exception", "crashed", "rejected", "denied"}
ERROR_FALSE = {"false", "0", "", "none", "null", "success", "succeeded", "ok",
               "completed", "complete", "done", "finished", "running",
               "pending", "in_progress", "started", "queued", "skipped"}
SEPARATORS = ("::", "__", ".", "_", "-", "/")

CODE_EXTS = {
    ".py", ".js", ".ts", ".html", ".css", ".sql", ".json", ".jsx", ".tsx",
    ".vue", ".php", ".go", ".rs", ".sh", ".bat", ".ps1", ".yaml", ".yml",
    ".c", ".cpp", ".cs", ".java", ".rb", ".kt", ".swift",
}
SCRATCHPAD_NAMES = {
    "task.md", "walkthrough.md", "scratchpad.md", "plan.md",
    "notes.md", "todo.md", "implementation_plan.md",
}


def compute_checksum(text):
    """SHA-256 нормализованного текста: переносы строк CRLF/CR сведены к \\n,
    конечный перенос строки не учитывается. Только это делает сумму
    сравнимой между сохранениями на Windows и на POSIX - сам код при этом
    сравнивается дословно, посимвольно."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def dig(obj, dotted):
    """Достаёт значение по пути вида 'message.content' или 'tool_args.path'."""
    if not dotted:
        return None
    cur = obj
    for part in str(dotted).split("."):
        if isinstance(cur, list):
            cur = cur[0] if cur else None
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def as_text(v):
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, ensure_ascii=False)
    except Exception:
        return str(v)


def parse_ts(v):
    """Возвращает aware-UTC datetime или None. None -> событие пропускаем."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        try:
            sec = v / 1000.0 if v > 1e11 else float(v)
            return datetime.fromtimestamp(sec, tz=timezone.utc)
        except Exception:
            return None
    if not isinstance(v, str):
        return None
    try:
        dt = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def classify_file(path_str):
    if not isinstance(path_str, str) or not path_str:
        return "unknown", "none", "none"
    p = Path(path_str)
    name, ext = p.name.lower(), p.suffix.lower()
    if name in SCRATCHPAD_NAMES or ".system_generated" in path_str.lower():
        return "scratchpad", name, name
    # Ключ - НОРМАЛИЗОВАННЫЙ ПУТЬ, а не расширение: иначе счётчик складывает
    # правки всех файлов одного типа и выдаёт их за правки одного файла.
    if ext in CODE_EXTS:
        return "code", str(p).replace("\\", "/").lower(), f"*{ext}"
    return "other", str(p).replace("\\", "/").lower(), f"*{ext}" if ext else "no_ext"


def is_edit_tool(name):
    n = (name or "").lower()
    return any(h in n for h in EDIT_TOOL_HINTS)


# Слова-подсказки для is_ask_human_tool - сравниваются с ЦЕЛЫМ сегментом имени
# (после разбивки по SEPARATORS), а не подстрокой: "task" в "manage_task" не
# должен зачесться за "ask" только потому, что содержит эти три буквы подряд.
ASK_HUMAN_TOOL_HINTS = ("ask", "question", "confirm")


def is_ask_human_tool(name):
    """Инструмент, которым агент обращается к человеку (спрашивает, просит
    подтверждение), а не выполняет действие сам. Нужен detect_workaround_chains
    - без этой проверки вызов ask_question между отказом и заменой считался бы
    ещё одной "другой" попыткой, хотя агент как раз спросил, а не промолчал."""
    if not name:
        return False
    parts = re.split(r"[_\-.:/]+", name.lower())
    return any(p.startswith(h) for p in parts for h in ASK_HUMAN_TOOL_HINTS)


def sanitize_sample(value, limit=40):
    """Обрезает образец сырого значения лога перед тем, как он попадёт в
    диагностику (а из неё — потенциально в audit_share.json). Путь или
    адрес там появиться не должны, даже случайно и даже в статус-строке."""
    s = str(value)[:limit]
    if "/" in s or "\\" in s or "@" in s:
        return "<скрыто: похоже на путь или адрес>"
    return s


def resolve_error(value, custom_error_values=None, custom_ok_values=None, custom_decline_values=None):
    """Возвращает (is_error, ambiguous, is_human_decline).

    Приоритет: значения, объявленные харнессом в field_map (error_values /
    ok_values), затем встроенные словари. Неизвестное значение НЕ считается
    ошибкой, но помечается как ambiguous, чтобы дефект был виден в диагностике.

    is_human_decline истинно, только если харнесс сам перечислил это ЗНАЧЕНИЕ
    статуса в human_decline_values - не по смыслу текста реплики, а по
    значению поля. Харнесс, где отказ человека и отказ инструмента используют
    один и тот же статус (нет отдельного значения для отказа человека),
    оставляет этот список пустым - тогда ось не измеряется, а не угадывается
    по содержимому.
    """
    if value is None:
        return False, False, False
    if isinstance(value, bool):
        return value, False, False
    if isinstance(value, (int, float)):
        return value != 0, False, False
    if isinstance(value, str):
        v = value.strip().strip('"').strip("'").lower()
        is_decline = v in {str(x).strip().lower() for x in (custom_decline_values or [])}
        if custom_error_values and v in {str(x).strip().lower() for x in custom_error_values}:
            return True, False, is_decline
        if custom_ok_values and v in {str(x).strip().lower() for x in custom_ok_values}:
            return False, False, False
        if v in ERROR_TRUE:
            return True, False, is_decline
        if v in ERROR_FALSE:
            return False, False, False
        return False, True, False          # неизвестный статус - НЕ ошибка, но помечаем
    return bool(value), False, False


def is_service_line(entry, fm):
    """Строка служебной телеметрии харнесса (снимок окружения, вывод хука,
    обновление списка доступных инструментов) - не действие агента, даже если
    у неё валидные время и роль. На Claude Code такие строки - около трети
    лога (тип attachment), и без этого разделения agent_steps считает их
    наравне с настоящими вызовами инструментов - завышение счёта примерно
    втрое на реальных данных (см. docs/decisions.md).

    Без объявленного различителя (field_map.line_type и
    field_map.service_line_values) ни одна строка служебной не считается -
    фиксированный код применяет то, что описано в discovery, а не гадает по
    форме записи."""
    line_type_path = fm.get("line_type")
    service_values = fm.get("service_line_values")
    if not line_type_path or not service_values:
        return False
    v = dig(entry, line_type_path)
    if v is None:
        return False
    return str(v).strip().lower() in {str(x).strip().lower() for x in service_values}


def clean_path(value):
    """Снимает кавычки и экранирование: '\"C:/p/f.py\"' -> 'C:/p/f.py'."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if v.startswith('"') and v.endswith('"') and len(v) > 1:
        try:
            v = json.loads(v)
        except Exception:
            v = v[1:-1]
    v = v.strip().strip('"').strip("'").replace('\\"', '"').replace("\\\\", "\\")
    return v or None


def extract_mcp_server(entry, fm):
    """Имя MCP-сервера, если харнесс зовёт MCP через общий диспетчер."""
    v = dig(entry, fm.get("mcp_server_arg"))
    if isinstance(v, str) and v.strip():
        return v.strip().strip('"')
    containers = [entry]
    for c in ARG_CONTAINERS:
        sub = entry.get(c)
        if isinstance(sub, dict):
            containers.append(sub)
        elif isinstance(sub, list) and sub and isinstance(sub[0], dict):
            containers.append(sub[0])
            inner = sub[0].get("args") or sub[0].get("input")
            if isinstance(inner, dict):
                containers.append(inner)
    for cont in containers:
        for k in MCP_SERVER_KEYS:
            v = cont.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip().strip('"')
    return None


def extract_tool_name(entry, fm):
    v = dig(entry, fm.get("tool_name"))
    if isinstance(v, str) and v.strip():
        return v.strip()
    for k in TOOL_NAME_KEYS:
        v = entry.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, dict):
            n = v.get("name")
            if isinstance(n, str) and n.strip():
                return n.strip()
    return None


def extract_target(entry, fm):
    """Путь к файлу: сперва по field_map, затем каскадом по типовым ключам."""
    v = clean_path(dig(entry, fm.get("tool_args_path")))
    if v:
        return v
    containers = [entry]
    for c in ARG_CONTAINERS:
        sub = entry.get(c)
        if isinstance(sub, dict):
            containers.append(sub)
        elif isinstance(sub, list) and sub and isinstance(sub[0], dict):
            containers.append(sub[0])
            inner = sub[0].get("args") or sub[0].get("input")
            if isinstance(inner, dict):
                containers.append(inner)
    for cont in containers:
        for k in FILE_ARG_KEYS:
            v = clean_path(cont.get(k))
            if v:
                return v
    return None


def matches_server(tool_name, server):
    """Инструмент принадлежит серверу, если имя сервера - префикс с разделителем."""
    if not tool_name or not server:
        return False
    t, s = tool_name.lower(), server.lower()
    if t == s:
        return True
    if t.startswith("mcp__") and t[5:].startswith(s):
        rest = t[5 + len(s):]
        return rest == "" or rest[0] in "_-.:/"
    if t.startswith(s):
        rest = t[len(s):]
        return rest[:2] == "::" or (rest and rest[0] in "_-.:/")
    return False


def mcp_namespace(tool_name):
    """'graphiti::search' / 'mcp__graphiti__x' / 'graphiti.search' -> 'graphiti'."""
    if not tool_name:
        return None
    if "::" in tool_name:
        return tool_name.split("::", 1)[0]
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__")
        return parts[1] if len(parts) >= 2 else None
    if "." in tool_name:
        return tool_name.split(".", 1)[0]
    return None


def link_tool_failures(events):
    """Привязывает строку-результат (несёт признак ошибки) к инструменту,
    вызванному на другой строке, и раскладывает отказ в одну из двух корзин -
    "failed_tool" (отказ инструмента) или "declined_tool" (отказ человека,
    is_human_decline) - события целиком.

    Способ привязки, в порядке приоритета: вызов и результат на одной строке
    ("same_row"); общий id (field_map.tool_call_id/tool_result_ref_id), если
    харнесс его объявил ("id"); ближайший предыдущий вызов в той же сессии не
    дальше MAX_TOOL_LINK_GAP строк ("adjacency"). Последний способ даёт только
    приблизительную привязку - соседний вызов может оказаться не тем, что
    реально привёл к этому отказу.

    Возвращает (unresolved, link_methods): unresolved - число отказов, которые
    не удалось привязать ни одним способом; link_methods - Counter по имени
    способа, использованному для КАЖДОГО удавшегося отказа (не по строкам
    вообще, а именно по привязанным отказам) - это и есть материал для
    collection_health.tool_attribution.

    Заодно, для настоящих отказов инструмента (не для отказа человека),
    запоминает в ev["failed_call_target"] цель ИМЕННО ТОГО вызова, что отказал
    (файл/путь, если извлёкся) - нужно детектору тихих обходов
    (detect_workaround_chains), чтобы отличить "тот же инструмент с другой
    целью" от простого повтора того же вызова. И ставит ev["call_failed"] =
    True на САМ ВЫЗОВ (не на строку-результат, которая при "id"/"adjacency"
    обычно другая строка и не несёт имени инструмента вовсе) - без этого
    detect_workaround_chains не мог бы узнать, что вызов, сделанный ВЗАМЕН
    отказавшего, сам тоже отказал, если харнесс не пишет вызов и результат на
    одной строке (a именно так устроено большинство реальных харнессов -
    "by_same_row" почти всегда 0, см. collection_health.tool_attribution)."""
    call_by_id = {}
    pending = []  # [(index, tool_name, tool_target)] в порядке появления в файле
    unresolved = 0
    link_methods = Counter()
    for idx, ev in enumerate(events):
        ev["call_failed"] = False  # по умолчанию; может стать True ниже по логу
        if ev["tool"]:
            if ev.get("call_id") is not None:
                call_by_id[str(ev["call_id"])] = (idx, ev["tool"], ev["target"])
            pending.append((idx, ev["tool"], ev["target"]))
        if not ev.get("is_result_row"):
            ev["failed_tool"] = None
            ev["declined_tool"] = None
            ev["failed_call_target"] = None
            continue
        if ev["tool"]:
            call_idx, target, call_target, method = idx, ev["tool"], ev["target"], "same_row"
        else:
            call_idx, target, call_target, method = None, None, None, None
            if ev.get("ref_id") is not None:
                hit = call_by_id.get(str(ev["ref_id"]))
                if hit is not None:
                    call_idx, target, call_target = hit
                    method = "id"
            if target is None:
                for pidx, ptool, ptarget in reversed(pending):
                    if idx - pidx > MAX_TOOL_LINK_GAP:
                        break
                    call_idx, target, call_target, method = pidx, ptool, ptarget, "adjacency"
                    break
        if not ev["err"]:
            ev["failed_tool"] = None
            ev["declined_tool"] = None
            ev["failed_call_target"] = None
            continue
        if target is None:
            unresolved += 1
            ev["failed_tool"] = None
            ev["declined_tool"] = None
            ev["failed_call_target"] = None
            continue
        link_methods[method] += 1
        if ev.get("is_human_decline"):
            ev["declined_tool"], ev["failed_tool"] = target, None
            ev["failed_call_target"] = None
        else:
            ev["failed_tool"], ev["declined_tool"] = target, None
            ev["failed_call_target"] = call_target
            if call_idx is not None:
                events[call_idx]["call_failed"] = True
    return unresolved, link_methods


# Окно поиска обхода вперёд от отказа - то же самое MAX_TOOL_LINK_GAP, которым
# уже ограничена привязка отказа к вызову (см. link_tool_failures). Отдельной
# константы для этого сознательно нет: одна и та же граница "дальше в логе
# связи уже нет" используется для обеих задач, а не изобретается заново.
def is_agent_text(ev):
    """Строка, где агент что-то написал сам, а не вызвал инструмент и не несёт
    результат чужого вызова, - "мысль" или текстовый ответ. Присутствие такой
    строки в промежутке между отказом и заменой значит, что агент хоть что-то
    сказал по пути; отсутствие - что обход прошёл вообще без единого слова."""
    return not ev["is_user"] and not ev["tool"] and not ev["is_result_row"]


def detect_workaround_chains(ep):
    """Ищет тихие обходы отказа инструмента внутри одного эпизода (список
    событий `ep`, уже нарезанный `segment()` и отсортированный по времени).

    Для каждого отказа (`ev["failed_tool"]` - только отказ ИНСТРУМЕНТА, не
    отказ человека: это разные сигналы, см. link_tool_failures) смотрит вперёд
    по событиям этого же эпизода, не дальше MAX_TOOL_LINK_GAP строк, не дальше
    WORKAROUND_MAX_GAP_MINUTES между соседними событиями и не дальше ближайшей
    реплики человека ИЛИ вызова инструмента, которым агент сам обращается к
    человеку (`is_ask_human_tool` - "не спросив" в находке иначе было бы не
    проверено, а просто написано). Если в этом промежутке агент делает ещё один
    вызов на ту же цель другим способом - другим инструментом либо тем же
    инструментом, но с другой целью (`target`), - это тихий обход. Замена не
    обязана сработать: сам факт того, что агент молча сменил подход, не спросив
    человека, уже находка независимо от исхода новой попытки - если новая
    попытка тоже отказала, поиск продолжается дальше в том же окне, пока не
    найдётся отличающийся вызов, не кончится окно, не пройдёт слишком много
    времени, не заговорит человек или не спросит сам агент.

    Несколько отказов подряд вокруг одной цели, без реплики человека между
    ними, схлопываются в ОДНУ цепочку: как только цепочка закрыта, разбор
    продолжается сразу после неё, а не с следующего отказа внутри неё - иначе
    один и тот же затык считался бы обходом по нескольку раз.

    Возвращает список цепочек: {session_prefix, ts, from_tool, to_tool,
    calls, duration_min, wordless}. `calls` - число попыток (вызовов) в
    цепочке, включая исходную отказавшую; `wordless` - агент не написал ни
    одного слова (см. is_agent_text) на всём протяжении цепочки."""
    n = len(ep)
    chains = []
    i = 0
    while i < n:
        ev = ep[i]
        if not ev.get("failed_tool"):
            i += 1
            continue
        ref_tool, ref_target = ev["failed_tool"], ev.get("failed_call_target")
        found_alt, alt_tool, last_idx = False, None, i
        any_text = False
        last_ts = ev["ts"]
        limit = min(i + MAX_TOOL_LINK_GAP, n - 1)
        j = i + 1
        while j <= limit:
            cur = ep[j]
            gap_min = (cur["ts"] - last_ts).total_seconds() / 60.0
            if gap_min > WORKAROUND_MAX_GAP_MINUTES:  # слишком большая пауза - разные события
                break
            last_ts = cur["ts"]
            if cur["is_user"]:              # человек вмешался - окно закрыто
                break
            if cur["tool"] and is_ask_human_tool(cur["tool"]):
                break                        # агент спросил человека - это не тихий обход
            if not cur["tool"]:
                if is_agent_text(cur):
                    any_text = True
                j += 1
                continue
            different = cur["tool"] != ref_tool or cur["target"] != ref_target
            if different:
                found_alt, alt_tool, last_idx = True, cur["tool"], j
                if cur.get("call_failed"):  # замена тоже отказала - ищем дальше
                    ref_tool, ref_target = cur["tool"], cur["target"]
                    j += 1
                    continue
                break                        # замена не отказала - цепочка закрыта
            last_idx = j                     # тот же инструмент, та же цель - обычный повтор
            if cur.get("call_failed"):
                j += 1
                continue
            break
        if found_alt:
            chains.append({
                "session_prefix": str(ep[0]["session_id"])[:8],
                "ts": ep[i]["ts"],
                "from_tool": ev["failed_tool"],
                "to_tool": alt_tool,
                "calls": 1 + sum(1 for k in range(i + 1, last_idx + 1) if ep[k]["tool"]),
                "duration_min": round((ep[last_idx]["ts"] - ep[i]["ts"]).total_seconds() / 60.0, 1),
                "wordless": not any_text,
            })
            i = last_idx + 1
        else:
            i += 1
    return chains


def median(lst):
    if not lst:
        return 0
    s = sorted(lst)
    n = len(s)
    return round(s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2, 2)


def percentile(lst, p):
    """p-квантиль (0..1) линейной интерполяцией между соседями по рангу."""
    if not lst:
        return 0
    s = sorted(lst)
    k = (len(s) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    if lo == hi:
        return round(s[lo], 2)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 2)


def spread(lst):
    """{p25, median, p75, max} одного списка чисел."""
    if not lst:
        return {"p25": 0, "median": 0, "p75": 0, "max": 0}
    return {"p25": percentile(lst, 0.25), "median": median(lst),
            "p75": percentile(lst, 0.75), "max": max(lst)}


KEY_AXES = ("duration_min", "user_turns", "agent_steps", "max_code_churn",
            "distinct_code_files", "steps_per_user_turn")
OTHER_MEDIAN_AXES = ("short_turns", "silent_recoveries", "visible_failures")


def spread_block(group_eps, key_axes=KEY_AXES):
    """{p25/median/p75/max} для key_axes (по умолчанию KEY_AXES) + median_* для
    OTHER_MEDIAN_AXES, посчитанные на одной группе эпизодов. key_axes сужается
    вызывающим кодом до осей без agent_steps/steps_per_user_turn, если
    step_classification_basis не заполнен (см. main()) - без него эти два
    числа не измерены и не публикуются вовсе, даже под чужим именем внутри
    baseline_medians."""
    out = {k: spread([e[k] for e in group_eps]) for k in key_axes}
    out.update({f"median_{k}": median([e[k] for e in group_eps]) for k in OTHER_MEDIAN_AXES})
    return out


def read_session(path, session_id, fm):
    """Читает один транскрипт по карте полей fm. Возвращает (events, stats)."""
    stats = {"lines": 0, "recognized": 0, "bad_json": 0, "bad_ts": 0, "marker": False,
             "ambiguous_error_values": 0, "error_value_samples": set(),
             "unresolved_tool_failures": 0, "link_methods": Counter(),
             "service_lines_excluded": 0}
    events, user_msgs = [], []
    try:
        fh = open(path, "r", encoding="utf-8", errors="ignore")
    except Exception:
        return [], [], stats
    with fh:
        for line in fh:                      # построчно, файл целиком в память не грузим
            line = line.strip()
            if not line:
                continue
            stats["lines"] += 1
            try:
                entry = json.loads(line)
            except Exception:
                stats["bad_json"] += 1
                continue
            if not isinstance(entry, dict):
                continue

            ts = parse_ts(dig(entry, fm.get("timestamp")))
            role = as_text(dig(entry, fm.get("role")))
            tool = extract_tool_name(entry, fm)
            content = as_text(dig(entry, fm.get("content")))
            for pat in (fm.get("content_strip_patterns") or []):
                if pat and pat in content:
                    content = content.split(pat, 1)[0]

            is_user = role.strip().lower() == str(fm.get("user_role_value", "user")).strip().lower()

            # Проверяем маркер только при is_user, не по всей строке лога.
            if is_user and AUDIT_MARKER in content:
                stats["marker"] = True
                return [], [], stats

            err_raw = dig(entry, fm.get("is_error"))
            if err_raw is None:
                for k in ("is_error", "isError", "error"):
                    if k in entry:
                        err_raw = entry.get(k)
                        break
            # Присутствие самого поля (а не его значение) отличает "это строка
            # с результатом вызова" от "на этой строке про ошибку вообще не
            # сказано" - на строке-мысли или строке-объявлении без своего
            # результата err_raw закономерно None, и это не то же самое, что
            # "результат есть и он успешный".
            is_result_row = err_raw is not None
            err, ambiguous, is_human_decline = resolve_error(
                err_raw, fm.get("error_values"), fm.get("ok_values"), fm.get("human_decline_values"))
            if ambiguous:
                stats["ambiguous_error_values"] += 1
                stats["error_value_samples"].add(sanitize_sample(err_raw))

            if not (ts or role or tool or err):
                continue
            stats["recognized"] += 1
            if ts is None:
                stats["bad_ts"] += 1
                continue

            # Служебная строка (см. is_service_line) распознана - schema_recognized
            # её учитывает - но действием агента не считается вовсе: не в events,
            # значит не в agent_steps, не в tool_global, не в сегментации.
            if is_service_line(entry, fm):
                stats["service_lines_excluded"] += 1
                continue

            if is_user:
                full = " ".join(content.split())
                if full:
                    user_msgs.append((session_id, ts, full[:USER_MSG_CAP], len(full)))

            events.append({
                "session_id": session_id,
                "ts": ts,
                "is_user": is_user,
                "is_short_user": is_user and len(content.strip()) <= SHORT_MSG_LIMIT,
                "tool": tool,
                "target": extract_target(entry, fm),
                "mcp_server": extract_mcp_server(entry, fm),
                "err": err,
                "is_human_decline": is_human_decline,
                "is_result_row": is_result_row,
                "call_id": dig(entry, fm.get("tool_call_id")) if tool else None,
                "ref_id": dig(entry, fm.get("tool_result_ref_id")) if is_result_row else None,
            })
    stats["unresolved_tool_failures"], stats["link_methods"] = link_tool_failures(events)
    return events, user_msgs, stats


def segment(events):
    events.sort(key=lambda e: e["ts"])
    out, batch, last = [], [], None
    for ev in events:
        if last is not None:
            d = (ev["ts"] - last).total_seconds() / 60.0
            if d >= HARD_SPLIT_MIN or (d >= INACTIVITY_SPLIT_MIN and ev["is_user"]):
                if batch:
                    out.append(batch)
                batch = []
        batch.append(ev)
        last = ev["ts"]
    if batch:
        out.append(batch)
    return out


GLOBAL_FILES = set()
GLOBAL_EXT = Counter()
GLOBAL_EXT_EPISODES = Counter()  # в скольких эпизодах расширение встретилось хотя бы раз
GLOBAL_WORKAROUND_CHAINS = []    # цепочки тихих обходов по всем эпизодам, см. measure()


def measure(ep, tz_off=0.0):
    users = [e for e in ep if e["is_user"]]
    code_churn, scratch_churn, tools = Counter(), Counter(), Counter()
    code_ext = {}
    silent, visible, pending = 0, 0, False

    # Цепочка ошибок считается ОДИН раз:
    #   ошибка -> успешный вызов до реплики человека  = тихое самовосстановление
    #   ошибка -> заговорил человек                   = видимый сбой
    for ev in ep:
        if ev["is_user"]:
            if pending:
                visible += 1
                pending = False
            continue
        if ev["err"]:                      # ошибка учитывается даже без имени инструмента
            pending = True
        elif pending and ev["tool"]:       # агент сделал успешный вызов и продолжил сам
            silent += 1
            pending = False
        if not ev["tool"]:
            continue
        tools[ev["tool"]] += 1
        if is_edit_tool(ev["tool"]):
            cat, key, ext = classify_file(ev["target"])
            if cat == "code":
                code_churn[key] += 1
                code_ext[key] = ext
                GLOBAL_FILES.add(key)
                GLOBAL_EXT[ext] += 1
            elif cat == "scratchpad":
                scratch_churn[key] += 1

    for ext in set(code_ext.values()):
        GLOBAL_EXT_EPISODES[ext] += 1

    GLOBAL_WORKAROUND_CHAINS.extend(detect_workaround_chains(ep))

    agent_steps = len(ep) - len(users)
    local_start = ep[0]["ts"] + timedelta(hours=tz_off)
    session_prefix = str(ep[0]["session_id"])[:8]
    return {
        "session_prefix": session_prefix,
        # session_prefix один на всю СЕССИЮ, а сессия может распасться на
        # несколько эпизодов (segment()) - двум разным эпизодам одной сессии
        # он достанется одинаковым. started_at - момент начала именно ЭТОГО
        # эпизода - вместе с session_prefix однозначно называет эпизод; без
        # него две разные задачи в одной сессии в отчёте неотличимы друг от
        # друга (см. docs/decisions.md).
        "started_at": ep[0]["ts"].isoformat(),
        # episode_ref - готовая строка для цитирования человеку (Часть 2/5):
        # хеш сессии сам по себе не уникален для эпизода (см. выше), а просить
        # харнесс каждый раз самому собирать его с started_at - хрупко, один
        # раз это уже привело к находке, показанной без обязательной оговорки
        # рядом (см. docs/decisions.md про silent_workarounds.wordless). Эпизоды
        # одной сессии разделяет как минимум INACTIVITY_SPLIT_MIN, так что
        # часы:минуты уже практически гарантированно различают их.
        "episode_ref": f"{session_prefix} {local_start.strftime('%d.%m %H:%M')}",
        "month": local_start.strftime("%Y-%m"),
        "steps_per_user_turn": round(agent_steps / max(len(users), 1), 1),
        "duration_min": round((ep[-1]["ts"] - ep[0]["ts"]).total_seconds() / 60.0, 1),
        "user_turns": len(users),
        "agent_steps": len(ep) - len(users),
        "short_turns": sum(1 for e in users if e["is_short_user"]),
        "max_code_churn": max(code_churn.values()) if code_churn else 0,
        "total_code_edits": sum(code_churn.values()),
        "distinct_code_files": len(code_churn),
        "max_scratchpad_churn": max(scratch_churn.values()) if scratch_churn else 0,
        "file_type": code_ext.get(code_churn.most_common(1)[0][0], "none") if code_churn else "none",
        "silent_recoveries": max(silent, 0),
        "visible_failures": visible,
        "top_tools": dict(tools.most_common(5)),
    }


# --- Служебные поля отчёта: install_id, история прогонов -------------------
# Хранятся отдельно от логики анализа выше: ничего здесь не влияет на то, как
# считаются эпизоды и медианы, только на то, что записывается в заголовок
# отчёта. Анкеты профиля больше нет: work_type/experience_months/team_size в
# отчёте всегда null. Единственное, что может прийти от человека сюда, -
# сверка self_check с прошлым разбором (см. Шаг 4) - решение, делиться ли
# файлом дальше, вообще не хранится нигде: отправки в этом инструменте нет.
PROFILE_FIELDS = ("work_type", "experience_months", "team_size")
# is_error и mcp_server_arg по формату discovery могут законно быть null -
# в missing_field_map не попадают. Эти пять - нет.
CORE_FIELD_MAP_KEYS = ("timestamp", "role", "content", "tool_name", "tool_args_path")


def load_state(path):
    """Построчный JSON (append-only): install/run записи.
    Возвращает install_id и список всех run-записей."""
    install_id, runs = None, []
    if not path.exists():
        return install_id, runs
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if not isinstance(rec, dict):
            continue
        t = rec.get("type")
        if t == "install" and rec.get("install_id"):
            install_id = rec["install_id"]
        elif t == "run":
            runs.append(rec)
    return install_id, runs


def append_state(path, record):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_self_check(path):
    """Единственное, что харнесс может подготовить в audit_profile_input.json:
    ответ на сверку с прошлым разбором (см. Шаг 4). Анкеты профиля больше нет,
    остальные поля из этого файла, если они там есть, игнорируются."""
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    sc = raw.get("self_check")
    return sc.strip() if isinstance(sc, str) and sc.strip() else None


SHELL_NAMES = ("bash", "powershell", "cmd", "zsh", "fish")


def detect_shell():
    """Вид оболочки, а не путь: basename без расширения, в нижнем регистре.
    Полный путь (а в нём — домашняя папка с именем пользователя) наружу не идёт."""
    raw = os.environ.get("SHELL") or os.environ.get("COMSPEC") or ""
    if not raw:
        return "unknown"
    stem = Path(raw).stem.lower()
    if stem == "pwsh":
        stem = "powershell"
    return stem if stem in SHELL_NAMES else "unknown"


def build_environment(disc, harness_detected_by, harness_version_looks_exact):
    disc = disc or {}
    sys_name = platform.system().lower()
    os_family = {"darwin": "macos"}.get(sys_name, sys_name) or None
    return {
        "harness": disc.get("harness_name"),
        "harness_version": disc.get("harness_version"),
        "harness_detected_by": harness_detected_by,
        "harness_version_looks_exact": harness_version_looks_exact,
        "os_family": os_family,
        "os_version": platform.version() or platform.release() or None,
        "shell": detect_shell(),
        "python_version": platform.python_version(),
        "step_granularity_note": disc.get("step_granularity_note"),
        "step_metrics_comparable_across_harnesses": False,
    }


def build_collection_health(status, diag, rank_dropped, warnings, partial_reasons,
                             days, sessions_total, episodes_total, role_plausibility=None,
                             tool_failures_unmeasured=False, human_declines_unmeasured=False,
                             tool_attribution=None, workaround_wordless_unmeasured=False,
                             flat_median_axes=None, mcp_inventory_unmeasured=False,
                             steps_unmeasured=False):
    diag = diag or {}
    dropped_records = {
        "files_missing": diag.get("files_missing", 0),
        "unrecognized_schema": diag.get("unrecognized_schema", 0),
        "skipped_audit_marker": diag.get("skipped_audit_marker", 0),
        "current_session_excluded": diag.get("current_session_excluded", 0),
        "bad_json_lines": diag.get("bad_json_lines", 0),
        "bad_timestamp_events": diag.get("bad_timestamp_events", 0),
    }
    lines_total = diag.get("lines_total", 0)
    recognized_total = diag.get("recognized_total", 0)
    schema_recognized = round(recognized_total / lines_total, 3) if lines_total else 0.0
    log_span_days = (days[-1] - days[0]).days + 1 if days else 0
    # Ключи записей лога, которые парсер встретил и не понял - сейчас не
    # считается вообще. null означает "не измеряли", а не "проверили, пусто":
    # это разные утверждения, пустой список читался бы как ложный "порядок".
    unrecognized_fields = None
    flat_axes = list(rank_dropped or [])
    if unrecognized_fields is None:
        flat_axes.append("unrecognized_fields")
    if tool_failures_unmeasured:
        flat_axes.append("tool_usage_global.failures")
    if human_declines_unmeasured:
        flat_axes.append("tool_usage_global.human_declines")
    if workaround_wordless_unmeasured:
        flat_axes.append("silent_workarounds.wordless")
    if mcp_inventory_unmeasured:
        flat_axes.append("mcp_inventory.dead_weight_servers")
    if steps_unmeasured:
        flat_axes.append("agent_steps")
        flat_axes.append("steps_per_user_turn")
        flat_axes.append("invisible_inefficiency")
    for axis_name in (flat_median_axes or []):
        flat_axes.append(f"baseline_medians.median_{axis_name}")
    return {
        "discovery_status": status,
        "partial_reasons": partial_reasons or [],
        "warnings": warnings or [],
        "schema_recognized": schema_recognized,
        "unrecognized_fields": unrecognized_fields,
        "missing_field_map": diag.get("missing_field_map", []),
        "unrecognized_statuses": diag.get("error_value_samples", []),
        "flat_axes": flat_axes,
        "dropped_records": dropped_records,
        "prior_audit_runs_excluded": diag.get("skipped_audit_marker", 0),
        "role_plausibility": role_plausibility or {"ok": None, "user_share": None, "reason": None},
        "log_span_days": log_span_days,
        "sessions_total": sessions_total,
        "episodes_total": episodes_total,
        "tool_attribution": tool_attribution or {"by_id": 0, "by_adjacency": 0, "by_same_row": 0,
                                                  "unresolved": 0, "per_tool_counts_approximate": False},
    }


MEMORY_TRANSPORTS = ("http", "stdio", "unknown")


def build_native_capabilities(raw_list):
    """Discovery отдаёт [{"code": ..., "description": ...}] - код уходит в
    share, описание остаётся только в полном отчёте."""
    out = []
    for item in raw_list or []:
        if not isinstance(item, dict):
            continue
        code = item.get("code")
        code = sanitize_sample(code, limit=40) if isinstance(code, str) and code.strip() else None
        desc = item.get("description")
        desc = desc if isinstance(desc, str) and desc.strip() else None
        out.append({"code": code, "description": desc})
    return out


def build_memory_mechanisms(raw_list, usage, mcp_direct):
    """Discovery отдаёт [{"name", "transport", "local", "description"}] -
    calls досчитывает сам скрипт по уже посчитанным вызовам MCP; description
    остаётся только в полном отчёте, в share не идёт."""
    out = []
    for item in raw_list or []:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        name = sanitize_sample(name, limit=60) if isinstance(name, str) and name.strip() else None
        transport = item.get("transport")
        transport = transport if transport in MEMORY_TRANSPORTS else "unknown"
        local = item.get("local") if isinstance(item.get("local"), bool) else None
        desc = item.get("description")
        desc = desc if isinstance(desc, str) and desc.strip() else None
        calls = usage.get(name) if name in usage else mcp_direct.get(name)
        if calls is None and name:
            for srv, cnt in mcp_direct.items():
                if srv.lower() == name.lower():
                    calls = cnt
                    break
        out.append({"name": name, "transport": transport, "local": local,
                     "calls": calls, "description": desc})
    return out


def explain_failure(diag):
    """Человеческое объяснение пустого результата: сколько сессий нашли, сколько
    и почему отсеяли, что можно сделать. Пустой отчёт без этого выглядит как
    сломанный инструмент, а не как честный итог сбора."""
    if not diag:
        return None
    listed = diag.get("files_listed", 0)
    read = diag.get("files_read", 0)
    parts = [f"Сессий найдено: {listed}, прочитано и разобрано: {read}."]
    reasons = []
    if diag.get("current_session_excluded"):
        reasons.append(f"{diag['current_session_excluded']} — это текущая сессия аудита")
    if diag.get("skipped_audit_marker"):
        reasons.append(f"{diag['skipped_audit_marker']} — прошлые сессии, где аудит "
                        f"реально запускали")
    if diag.get("files_missing"):
        reasons.append(f"{diag['files_missing']} — путь из discovery не существует")
    if diag.get("unrecognized_schema"):
        reasons.append(f"{diag['unrecognized_schema']} — схема лога не распознана вообще")
    if reasons:
        parts.append("Отсеяно: " + "; ".join(reasons) + ".")
    parts.append("Анализировать нечего.")
    suggestions = []
    if read == 0 and listed > 0 and (diag.get("skipped_audit_marker") or diag.get("current_session_excluded")):
        suggestions.append("нужна ещё хотя бы одна сессия, не связанная с запуском или "
                            "редактированием самого этого промпта")
    if diag.get("unrecognized_schema"):
        suggestions.append("проверь field_map в audit_discovery.json на реальных строках лога")
    if diag.get("files_missing"):
        suggestions.append("проверь пути sessions[].path в audit_discovery.json")
    if not suggestions:
        suggestions.append("проверь audit_discovery.json целиком — что-то в схеме или путях не сошлось")
    parts.append("Что можно сделать: " + "; ".join(suggestions) + ".")
    return " ".join(parts)


def _dedupe_episode_ids(*episode_lists):
    """session_prefix называет СЕССИЮ (см. measure()), а не эпизод - одна
    сессия может распасться на несколько эпизодов с одним и тем же префиксом.
    started_at и episode_ref рядом с ним уже должны разводить их (см.
    docs/decisions.md), но если это когда-нибудь снова сломается - например,
    started_at потеряется при отборе полей, - прогон у человека на чужой
    машине не должен упасть трассировкой вместо отчёта: это потерянный
    пользователь на первом же запуске. Вместо падения - конфликт разводится
    молча: конфликтующей записи достаётся уникальный суффикс и в
    session_prefix, и в episode_ref, а число конфликтов возвращается вызывающему
    для diagnostics (человек его не видит - см. Часть 4/5 промта). Та же
    проверка, но падающая при конфликте, - в tools/check_episode_ids.py,
    для наших собственных прогонов, не для чужой машины."""
    seen = {}
    conflicts = 0
    for lst in episode_lists:
        for e in lst:
            key = (e["session_prefix"], e["started_at"])
            # agent_steps может отсутствовать в самой записи (см. top_anomaly_keys
            # в main() - ключ вырезан целиком, если steps_unmeasured) - .get(),
            # а не [], чтобы это не роняло прогон на чужой машине.
            fingerprint = (e["duration_min"], e.get("agent_steps"), e["user_turns"])
            prev = seen.get(key)
            if prev is not None and prev != fingerprint:
                conflicts += 1
                suffix = f"-dup{conflicts}"
                e["session_prefix"] = e["session_prefix"] + suffix
                if "episode_ref" in e:
                    e["episode_ref"] = e["episode_ref"] + suffix
                key = (e["session_prefix"], e["started_at"])
            seen[key] = fingerprint
    return conflicts


def main():
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        code_checksum = compute_checksum(Path(__file__).read_text(encoding="utf-8"))
    except Exception:
        # Не смогли прочитать себя (нестандартный запуск, __file__ не файл) -
        # честно null, а не выдуманное значение.
        code_checksum = None
    state_path = Path("audit_state.jsonl").resolve()
    profile_input_path = Path("audit_profile_input.json").resolve()

    install_id, runs = load_state(state_path)
    if not install_id:
        install_id = secrets.token_hex(8)          # 16 hex, невосстановим в принципе
        append_state(state_path, {"type": "install", "install_id": install_id,
                                   "created_at": now_iso})

    self_check = load_self_check(profile_input_path)
    merged_profile = {k: None for k in PROFILE_FIELDS}  # анкеты нет - поля всегда пусты

    prev_run = runs[-1] if runs else None
    run_seq = (prev_run.get("run_seq", 0) if prev_run else 0) + 1
    prev_run_at = prev_run.get("at") if prev_run else None
    prev_metric_version = prev_run.get("metric_version") if prev_run else None

    def build_meta(tz_offset_minutes):
        return {
            "schema_version": SCHEMA_VERSION,
            "metric_version": METRIC_VERSION,
            "metric_changes": METRIC_CHANGES,
            "tool_version": TOOL_VERSION,
            "generated_at": now_iso,
            "tz_offset_minutes": tz_offset_minutes,
            "install_id": install_id,
            "run_seq": run_seq,
            "prev_run_at": prev_run_at,
            "prev_metric_version": prev_metric_version,
            "code_checksum": code_checksum,
        }

    def write_failure(message, disc=None, diag=None, tz_offset_minutes=None,
                       harness_detected_by=None, harness_version_looks_exact=None):
        env = build_environment(disc, harness_detected_by, harness_version_looks_exact)
        health = build_collection_health(
            "failed", diag, [], [], [], None,
            sessions_total=(diag or {}).get("files_listed", 0), episodes_total=0)
        meta = build_meta(tz_offset_minutes)
        profile_full = dict(merged_profile, self_check=self_check)
        profile_share = dict(merged_profile)
        diagnosis = explain_failure(diag)
        header = {"meta": meta, "environment": env, "collection_health": health}
        report_partial = dict(header, profile=profile_full, status="ERROR",
                               message=message, diagnosis=diagnosis)
        share_partial = dict(header, profile=profile_share)
        Path("workspace_audit_report.json").resolve().write_text(
            json.dumps(report_partial, ensure_ascii=False, indent=2), encoding="utf-8")
        Path("audit_share.json").resolve().write_text(
            json.dumps(share_partial, ensure_ascii=False, indent=2), encoding="utf-8")
        append_state(state_path, {"type": "run", "run_seq": run_seq, "at": now_iso,
                                   "schema_version": SCHEMA_VERSION,
                                   "metric_version": METRIC_VERSION, "status": "failed"})
        print("\n--- АУДИТ ОСТАНОВЛЕН: анализировать нечего ---")
        print(message)
        if diagnosis:
            print(diagnosis)
        print("\nЗаголовок отчёта всё равно записан на диск (workspace_audit_report.json, "
              "audit_share.json): meta и environment заполнены, "
              "collection_health.discovery_status = \"failed\".")
        print(f"\nКонтрольная сумма исполняемого кода (SHA-256, без переносов строк): "
              f"{code_checksum}")
        print("Сверь её с суммой, указанной в промте рядом с кодом Шага 2 - не совпадает, "
              "значит этот прогон посчитан не каноническим скриптом.")

    disc_path = Path(sys.argv[1] if len(sys.argv) > 1 else "audit_discovery.json")
    if not disc_path.exists():
        write_failure(f"НЕ НАЙДЕН {disc_path}. Сначала выполни Шаг 1 (discovery).")
        return 1
    try:
        disc = json.loads(disc_path.read_text(encoding="utf-8"))
    except Exception as e:
        write_failure(f"{disc_path} не читается как JSON: {e}")
        return 1

    # Файл с репликами создаётся только с явного разрешения человека - вопрос
    # задаётся харнессом в начале Шага 1, до чтения логов, а ответ приходит
    # сюда через discovery. Без согласия эта переменная False, и текстовый
    # дамп реплик просто не пишется - остальные метрики (включая brag_stats по
    # числу и длине сообщений, посчитанные раньше по all_user_msgs) от неё не
    # зависят, зависит только сам файл и находка REPEATED_COMPLAINT в Части 2.
    collect_messages = bool(disc.get("collect_message_texts"))

    # Кто узнал имя/версию харнесса - сам харнесс (declared) или разведка
    # вывела по путям/имени процесса (inferred) - это разные вопросы. Первое
    # объявляет сам discovery; второе - "похожа ли версия на точный билд" -
    # отдельная проверка ниже (harness_version_looks_exact).
    hdb_raw = disc.get("harness_detected_by")
    harness_detected_by = hdb_raw if hdb_raw in ("declared", "inferred") else None
    if harness_detected_by is None:
        # Без объявленного способа определения версия могла быть просто
        # правдоподобной догадкой - тот же провал, что и с выдуманным
        # инвентарём MCP (см. docs/decisions.md): факт без источника не идёт
        # в отчёт как есть, поле остаётся пустым, а не тем, что модель написала.
        disc["harness_version"] = None
    hv = str(disc.get("harness_version") or "").strip()
    version_ok = bool(re.match(r"^\d+\.\d+", hv)) and not re.match(r"^\d+\.0$", hv)
    harness_version_looks_exact = version_ok if hv else None

    # Текущая (живая) сессия аудита должна быть исключена явно, по id из
    # discovery - AUDIT_MARKER в read_session ловит только то, что уже
    # записалось в транскрипт, а не то, что пишется прямо сейчас.
    current_session_id = disc.get("current_session_id")
    current_session_id = str(current_session_id).strip() if current_session_id else None

    tz_raw = disc.get("utc_offset_hours")
    tz_source = disc.get("utc_offset_source")
    # Число здесь может быть настоящим смещением, взятым из системы, или
    # правдоподобной догадкой по стране - то же место, где правдоподобное
    # однажды уже подставили вместо признания "не знаю" (см. docs/decisions.md,
    # случай про параллельные сессии). Доверяем числу, только если харнесс
    # прямо сказал, что взял его из системы.
    try:
        tz_off = float(tz_raw) if tz_source == "system" else None
        tz_known = tz_off is not None
    except (TypeError, ValueError):
        tz_off, tz_known = None, False
    if tz_off is None:
        tz_off = 0.0
    tz_offset_minutes = int(round(tz_off * 60)) if tz_known else None

    fm = disc.get("field_map") or {}
    missing_field_map = sorted(k for k in CORE_FIELD_MAP_KEYS if not fm.get(k))

    # Без основания (что реально проверено в логе - см. discovery) числу
    # agent_steps доверять нельзя: харнесс мог посчитать служебную телеметрию
    # (см. is_service_line) действиями агента, как уже случилось на Claude
    # Code (см. docs/decisions.md). Метрики по числу шагов гасятся ЦЕЛИКОМ,
    # а не публикуются нулём или с оговоркой - см. везде ниже, где встречается
    # steps_unmeasured.
    step_basis = str(disc.get("step_classification_basis") or "").strip()
    steps_unmeasured = not bool(step_basis)
    key_axes = KEY_AXES if not steps_unmeasured else tuple(
        k for k in KEY_AXES if k not in ("agent_steps", "steps_per_user_turn"))

    sessions = disc.get("sessions") or []
    if not sessions:
        write_failure("В audit_discovery.json пустой список sessions. Аудит невозможен.",
                       disc=disc, tz_offset_minutes=tz_offset_minutes,
                       harness_detected_by=harness_detected_by,
                       harness_version_looks_exact=harness_version_looks_exact)
        return 1

    by_sess, tool_global, tool_failures, tool_human_declines, mcp_direct = (
        {}, Counter(), Counter(), Counter(), Counter())
    link_methods_global = Counter()
    all_user_msgs = []
    diag = {"files_listed": len(sessions), "files_read": 0, "files_missing": 0,
            "unrecognized_schema": 0, "skipped_audit_marker": 0,
            "current_session_excluded": 0,
            "bad_json_lines": 0, "bad_timestamp_events": 0,
            "ambiguous_error_values": 0, "error_value_samples": [],
            "events_with_file_path": 0, "events_total": 0,
            "result_row_events": 0,
            "user_turns_total": 0, "short_user_turns_total": 0,
            "lines_total": 0, "recognized_total": 0,
            "unresolved_tool_failures": 0, "service_lines_excluded": 0,
            "missing_field_map": missing_field_map}
    err_samples = set()

    for item in sessions:
        path, sid = item.get("path"), item.get("session_id") or "unknown"
        if current_session_id and str(sid) == current_session_id:
            diag["current_session_excluded"] += 1
            continue
        if not path or not Path(path).exists():
            diag["files_missing"] += 1
            continue
        evs, umsgs, st = read_session(path, sid, fm)
        all_user_msgs.extend(umsgs)
        diag["files_read"] += 1
        diag["lines_total"] += st["lines"]
        diag["recognized_total"] += st["recognized"]
        diag["bad_json_lines"] += st["bad_json"]
        diag["bad_timestamp_events"] += st["bad_ts"]
        diag["ambiguous_error_values"] += st["ambiguous_error_values"]
        diag["unresolved_tool_failures"] += st["unresolved_tool_failures"]
        diag["service_lines_excluded"] += st["service_lines_excluded"]
        link_methods_global.update(st["link_methods"])
        err_samples |= st["error_value_samples"]
        if st["marker"]:
            diag["skipped_audit_marker"] += 1
            continue
        if st["lines"] > 0 and st["recognized"] == 0:
            diag["unrecognized_schema"] += 1
            continue
        if evs:
            by_sess.setdefault(sid, []).extend(evs)
            for e in evs:
                diag["events_total"] += 1
                if e["is_result_row"]:
                    diag["result_row_events"] += 1
                if e["target"]:
                    diag["events_with_file_path"] += 1
                if e["tool"]:
                    tool_global[e["tool"]] += 1
                if e.get("failed_tool"):
                    tool_failures[e["failed_tool"]] += 1
                if e.get("declined_tool"):
                    tool_human_declines[e["declined_tool"]] += 1
                if e["mcp_server"]:
                    mcp_direct[e["mcp_server"]] += 1
                if e["is_user"]:
                    diag["user_turns_total"] += 1
                    if e["is_short_user"]:
                        diag["short_user_turns_total"] += 1

    diag["error_value_samples"] = sorted(err_samples)[:5]

    if not by_sess:
        write_failure("Пригодных событий нет. Проверь field_map в discovery.",
                       disc=disc, diag=diag, tz_offset_minutes=tz_offset_minutes,
                       harness_detected_by=harness_detected_by,
                       harness_version_looks_exact=harness_version_looks_exact)
        return 1

    episodes, dropped, kept_autonomous = [], 0, 0
    for sid, evs in by_sess.items():
        for ep in segment(evs):
            n_user = sum(1 for e in ep if e["is_user"])
            n_agent = len(ep) - n_user
            if n_user < MIN_USER_TURNS:
                # Одна реплика и сотни шагов агента - это не "пустой чат",
                # а автономная петля. Такие эпизоды сохраняем - но только если
                # числу шагов вообще можно доверять (см. steps_unmeasured):
                # без него безопасный выбор - отбросить короткий эпизод, а не
                # решить по числу, которое может быть выдумано.
                if steps_unmeasured or n_agent < MIN_STEPS_FOR_INVISIBLE:
                    dropped += 1
                    continue
                kept_autonomous += 1
            episodes.append(measure(ep, tz_off))
    if not episodes:
        write_failure(f"Эпизодов нет (коротких отброшено: {dropped}).",
                       disc=disc, diag=diag, tz_offset_minutes=tz_offset_minutes,
                       harness_detected_by=harness_detected_by,
                       harness_version_looks_exact=harness_version_looks_exact)
        return 1

    medians = spread_block(episodes, key_axes)

    user_share = round(diag["user_turns_total"] / diag["events_total"], 3) if diag["events_total"] else None
    role_ok, role_reason = True, None
    if diag["events_total"] >= ROLE_PLAUSIBILITY_MIN_EVENTS:
        if user_share is not None and user_share > ROLE_SHARE_SUSPICIOUS:
            role_ok = False
            role_reason = (f"реплик человека {user_share * 100:.0f}% от всех событий - в разы больше "
                           f"образца нормы (~{ROLE_SHARE_REFERENCE * 100:.0f}%). Похоже, "
                           f"field_map.role/user_role_value путает ответы инструментов с репликами "
                           f"человека.")
        elif not steps_unmeasured and medians["steps_per_user_turn"]["median"] < ROLE_STEPS_PER_TURN_SUSPICIOUS:
            role_ok = False
            role_reason = (f"медиана действий агента на реплику человека - "
                           f"{medians['steps_per_user_turn']['median']}, в разы ниже образца нормы "
                           f"(~{ROLE_STEPS_PER_TURN_REFERENCE}). Похоже, часть ответов инструментов "
                           f"посчитана репликами человека.")
    role_plausibility = {"ok": role_ok, "user_share": user_share, "reason": role_reason}

    # Групп с эпизодами меньше MIN_EPISODES_PER_GROUP медиану не публикуем,
    # только insufficient_data.
    total_edits_all = sum(GLOBAL_EXT.values())
    file_type_distribution = {
        ext: {
            "edits_share": round(cnt / total_edits_all, 3) if total_edits_all else 0,
            "episodes_share": round(GLOBAL_EXT_EPISODES.get(ext, 0) / len(episodes), 3),
        }
        for ext, cnt in GLOBAL_EXT.most_common()
    }
    groups_by_file_type = {}
    for e in episodes:
        groups_by_file_type.setdefault(e["file_type"], []).append(e)
    medians_by_file_type = {}
    for ft, group_eps in groups_by_file_type.items():
        if len(group_eps) < MIN_EPISODES_PER_GROUP:
            medians_by_file_type[ft] = {"n_episodes": len(group_eps), "insufficient_data": True}
            continue
        medians_by_file_type[ft] = dict(n_episodes=len(group_eps), insufficient_data=False,
                                         **spread_block(group_eps, key_axes))

    # По месяцам локального времени (см. tz_off).
    groups_by_month = {}
    for e in episodes:
        groups_by_month.setdefault(e["month"], []).append(e)
    distinct_months = sorted(groups_by_month)
    medians_by_month = {"months_found": len(distinct_months),
                         "insufficient_data": len(distinct_months) < 2, "by_month": {}}
    if len(distinct_months) >= 2:
        for mo, group_eps in groups_by_month.items():
            if len(group_eps) < MIN_EPISODES_PER_GROUP:
                medians_by_month["by_month"][mo] = {"n_episodes": len(group_eps),
                                                      "insufficient_data": True}
            else:
                medians_by_month["by_month"][mo] = dict(
                    n_episodes=len(group_eps), insufficient_data=False,
                    **spread_block(group_eps, key_axes))

    # Ось, у которой одно и то же значение во всех эпизодах, не различает их:
    # её перцентиль равен 1.0 везде и только раздувает балл. Исключаем и говорим об этом.
    RANK_ALL = ["max_code_churn", "user_turns", "short_turns", "duration_min", "visible_failures"]
    cols_all = {k: [e[k] for e in episodes] for k in RANK_ALL}
    rank_used = [k for k in RANK_ALL if len(set(cols_all[k])) > 1]
    rank_dropped = [k for k in RANK_ALL if k not in rank_used]
    if not rank_used:
        rank_used = RANK_ALL[:1]
    # Ось, где одно значение занимает почти всё распределение, различает эпизоды
    # слабо. Не исключаем (она всё же несёт сигнал), но помечаем в отчёте.
    low_info = {}
    for k in rank_used:
        vals = cols_all[k]
        share = max(Counter(vals).values()) / len(vals)
        if share >= 0.9:
            low_info[k] = round(share, 3)
    for e in episodes:
        e["anomaly_score"] = round(
            sum(sum(1 for v in cols_all[k] if v <= e[k]) / len(cols_all[k]) for k in rank_used), 3)
    episodes.sort(key=lambda e: e["anomaly_score"], reverse=True)

    # silent_recoveries не входит в RANK_ALL (в ранжировании эпизодов не
    # участвует), но печатать медиану по оси, одинаковой у всех эпизодов, вводит
    # в заблуждение точно так же, как и с ранжируемыми осями - "0.0" тогда
    # значит "у всех одно и то же", а не "агент восстанавливался редко".
    silent_recoveries_flat = len({e["silent_recoveries"] for e in episodes}) <= 1
    flat_median_axes = [k for k in OTHER_MEDIAN_AXES if k in rank_dropped]
    if silent_recoveries_flat and "silent_recoveries" not in flat_median_axes:
        flat_median_axes.append("silent_recoveries")

    # Список установленных серверов существует, только если у него есть
    # файл-источник - список инструментов из собственного контекста харнесса
    # (системный промт) источником не считается никогда, это не то, что
    # человек установил сам (см. docs/decisions.md, находка про выдуманный
    # инвентарь MCP). Без источника declared остаётся пустым независимо от
    # того, что харнесс всё-таки записал в mcp_servers - находка "мёртвый
    # груз" на этом принципе не строится вовсе, см. mcp_inventory ниже.
    mcp_src = disc.get("mcp_servers_source")
    mcp_source_ok = isinstance(mcp_src, dict) and bool(mcp_src.get("file"))
    mcp_declared_raw = disc.get("mcp_servers")
    declared = mcp_declared_raw if (mcp_source_ok and isinstance(mcp_declared_raw, list)) else []
    aliases = disc.get("mcp_server_aliases") or {}   # {"имя в конфиге": ["имя в рантайме"]}
    usage, matched_tools = {}, set()
    for s in declared:
        names = {s.lower()} | {str(a).lower() for a in (aliases.get(s) or [])}
        total = 0
        for name, cnt in tool_global.items():
            if any(matches_server(name, n) for n in names):
                total += cnt
                matched_tools.add(name)
        for srv, cnt in mcp_direct.items():        # вызовы через общий диспетчер
            if srv.lower() in names:
                total += cnt
        usage[s] = total
    # инструменты с namespace-разделителем, не отнесённые ни к одному серверу
    unattributed = sorted({mcp_namespace(n) for n in tool_global
                           if n not in matched_tools and mcp_namespace(n)})
    declared_lc = {s.lower() for s in declared}
    for v in aliases.values():
        declared_lc |= {str(a).lower() for a in (v or [])}
    # Без подтверждённого источника declared пуст намеренно (см. выше) - но
    # "необъявленный" имеет смысл только относительно ЗАЯВЛЕННОГО списка.
    # Если списка нет, а не пуст, всё вызванное считалось бы "необъявленным"
    # и завело бы ложное предупреждение, хотя на деле мы просто не знаем.
    undeclared_used = ({s: c for s, c in mcp_direct.items() if s.lower() not in declared_lc}
                        if mcp_source_ok else {})

    # invisible: агент работал автономно заметно больше обычного ДЛЯ ЭТОГО ЖЕ
    # человека. Сортировка - по абсолютному числу шагов, не по отношению.
    # Вся эта находка построена на agent_steps/steps_per_user_turn - без
    # steps_unmeasured==False ей нет смысла: список остаётся пустым, а не
    # посчитанным по недостоверному числу.
    if steps_unmeasured:
        ratio_cut, invisible = None, []
    else:
        ratio_cut = medians["steps_per_user_turn"]["median"] * INVISIBLE_RATIO_FACTOR
        invisible = [e for e in episodes
                     if e["agent_steps"] >= MIN_STEPS_FOR_INVISIBLE
                     and e["steps_per_user_turn"] >= ratio_cut]
        invisible.sort(key=lambda e: (e["agent_steps"], e["duration_min"]), reverse=True)

    # tz_off - из discovery; если нет, считаем по UTC и помечаем это в отчёте.
    shift = timedelta(hours=tz_off)

    local = [(ts + shift) for _s, ts, _t, _l in all_user_msgs]
    hour_hist = Counter(t.hour for t in local)
    night = sum(c for h, c in hour_hist.items() if h < 6)
    evening = sum(c for h, c in hour_hist.items() if h >= 22)
    peak_hour = hour_hist.most_common(1)[0][0] if hour_hist else None
    weekend = sum(1 for t in local if t.weekday() >= 5)

    days = sorted({t.date() for t in local})
    streak = best = 0
    prev = None
    for d in days:
        streak = streak + 1 if prev and (d - prev).days == 1 else 1
        best = max(best, streak)
        prev = d
    by_day = Counter(t.date() for t in local)
    busiest = by_day.most_common(1)[0] if by_day else (None, 0)
    total_hours = round(sum(e["duration_min"] for e in episodes) / 60.0, 1)
    longest = max(episodes, key=lambda e: e["duration_min"])
    biggest = None if steps_unmeasured else max(episodes, key=lambda e: e["agent_steps"])

    brag = {
        "period_from": days[0].isoformat() if days else None,
        "period_to": days[-1].isoformat() if days else None,
        "active_days": len(days),
        "longest_streak_days": best,
        "hours_with_agent": total_hours,
        "tasks_completed": len(episodes),
        "messages_written": len(all_user_msgs),
        "characters_typed": sum(l for _s, _t, _x, l in all_user_msgs),
        "agent_actions_total": sum(tool_global.values()),
        "commands_run": sum(c for n, c in tool_global.items() if "command" in n.lower()
                            or "terminal" in n.lower() or "bash" in n.lower()),
        "code_edits_total": sum(GLOBAL_EXT.values()),
        "code_files_touched": len(GLOBAL_FILES),
        "languages_top": dict(GLOBAL_EXT.most_common(5)),
        "longest_task_min": longest["duration_min"],
        "biggest_task_agent_steps": (biggest["agent_steps"] if biggest else None),
        "timezone": {
            "utc_offset_hours": tz_off,
            "source": "discovery" if tz_known else "не указан, считалось по UTC",
        },
        "when_you_work": {
            "peak_hour_local": peak_hour,
            "night_share_00_06": round(night / len(local), 3) if local else 0,
            "late_share_after_22": round(evening / len(local), 3) if local else 0,
            "weekend_share": round(weekend / len(local), 3) if local else 0,
            "busiest_day": busiest[0].isoformat() if busiest[0] else None,
            "busiest_day_messages": busiest[1],
            "messages_by_hour": {str(h): hour_hist.get(h, 0) for h in range(24)},
        },
    }

    tool_failures_unmeasured = bool(tool_global) and not any(tool_failures.values())
    human_declines_unmeasured = bool(tool_global) and not fm.get("human_decline_values")
    # Если признак ошибки (field_map.is_error) стоит почти на КАЖДОЙ строке
    # лога (не только на результатах вызовов - как status-поле шага в
    # Antigravity), is_result_row перестаёт отличать "агент что-то написал" от
    # "агент вызвал инструмент": is_agent_text не сможет сработать ни разу, и
    # wordless_total будет равен total не потому, что обходы правда немые, а
    # потому, что эта ось структурно не измерена этим форматом логов.
    workaround_wordless_unmeasured = (
        diag["events_total"] > 0
        and diag["result_row_events"] / diag["events_total"] >= 0.95
    )
    tool_attribution = {
        "by_id": link_methods_global.get("id", 0),
        "by_adjacency": link_methods_global.get("adjacency", 0),
        "by_same_row": link_methods_global.get("same_row", 0),
        "unresolved": diag["unresolved_tool_failures"],
        "per_tool_counts_approximate": link_methods_global.get("adjacency", 0) > 0,
    }

    # Тихие обходы (см. detect_workaround_chains, вызывается из measure() на
    # каждом эпизоде): агент сам сменил подход после отказа инструмента, не
    # спросив человека. Как и tool_usage_global.failures, ось имеет смысл,
    # только если сами отказы инструмента вообще измеряются в этом формате
    # логов - если tool_failures_unmeasured, находку не заводить (см. Часть 2).
    workaround_chains = GLOBAL_WORKAROUND_CHAINS
    workaround_calls = [c["calls"] for c in workaround_chains]
    workaround_pairs = Counter((c["from_tool"], c["to_tool"]) for c in workaround_chains)
    silent_workarounds = {
        "total": len(workaround_chains),
        "tool_failures_total": sum(tool_failures.values()),
        "wordless_total": sum(1 for c in workaround_chains if c["wordless"]),
        "top_pairs": [{"from_tool": ft, "to_tool": tt, "count": cnt}
                      for (ft, tt), cnt in workaround_pairs.most_common(5)],
        # Примеры - только для приватного отчёта: session_prefix + время
        # позволяют найти место в своей истории. В share идут только числа и
        # имена инструментов (top_pairs), без session_prefix и без времени.
        "examples": [
            {"session_prefix": c["session_prefix"], "ts": c["ts"].isoformat(),
             "from_tool": c["from_tool"], "to_tool": c["to_tool"],
             "calls": c["calls"], "duration_min": c["duration_min"], "wordless": c["wordless"]}
            for c in sorted(workaround_chains, key=lambda c: (c["calls"], c["duration_min"]),
                             reverse=True)[:3]
        ],
    }
    # После ограничения окна обхода по времени (WORKAROUND_MAX_GAP_MINUTES)
    # длина цепочки почти всегда вырождается в одно и то же число (обычно 2:
    # отказ и одна замена) - таблица "медиана/максимум" из одного повторяющегося
    # значения не находка, а шум. Публикуем длину цепочки, только если она хоть
    # немного различается между цепочками; иначе в отчёте остаются total,
    # tool_failures_total, wordless_total и top_pairs - без разговора о длине.
    if len(set(workaround_calls)) > 1:
        longest_workaround = max(workaround_chains, key=lambda c: (c["calls"], c["duration_min"]))
        silent_workarounds["longest_chain_calls"] = longest_workaround["calls"]
        silent_workarounds["longest_chain_duration_min"] = longest_workaround["duration_min"]
        silent_workarounds["median_chain_calls"] = median(workaround_calls)
    silent_workarounds_share = {k: v for k, v in silent_workarounds.items() if k != "examples"}

    # discovery_status/partial_reasons - только про СБОР данных: файлы не
    # нашлись, схема не распозналась, статус ошибки неоднозначен, из событий
    # не извлеклись пути или короткие реплики. Сбор либо получился, либо нет.
    partial_reasons = []
    if diag["files_missing"]:
        partial_reasons.append("files_missing")
    if diag["unrecognized_schema"]:
        partial_reasons.append("unrecognized_schema")
    if diag["ambiguous_error_values"]:
        partial_reasons.append("ambiguous_error_values")
    if diag["events_total"] and diag["events_with_file_path"] == 0:
        partial_reasons.append("no_file_paths")
    if diag["user_turns_total"] > 20 and diag["short_user_turns_total"] == 0:
        partial_reasons.append("no_short_turns")
    if diag["skipped_audit_marker"]:
        partial_reasons.append("prior_audit_sessions_excluded")
    if diag["unresolved_tool_failures"]:
        partial_reasons.append("unresolved_tool_failures")
    if human_declines_unmeasured:
        partial_reasons.append("human_declines_unmeasured")
    if tool_attribution["per_tool_counts_approximate"]:
        partial_reasons.append("tool_attribution_approximate")
    if workaround_wordless_unmeasured:
        partial_reasons.append("workaround_wordless_unmeasured")
    if not mcp_source_ok:
        partial_reasons.append("mcp_inventory_unmeasured")
    if steps_unmeasured:
        partial_reasons.append("step_classification_unmeasured")
    if not role_ok:
        partial_reasons.append("role_detection_suspicious")
    discovery_status = "partial" if partial_reasons else "ok"

    # warnings - находки ИНВЕНТАРЯ, а не поломка сбора: сбор прошёл штатно, но
    # в устройстве харнесса или в данных есть что заметить отдельно от того,
    # удалось ли вообще собрать статистику.
    warnings = []
    if rank_dropped:
        warnings.append("flat_ranking_axes")
    if low_info:
        warnings.append("low_information_axes")
    if undeclared_used:
        warnings.append("undeclared_mcp_servers")
    if harness_version_looks_exact is not True:
        warnings.append("harness_version_not_exact")
    if not current_session_id:
        warnings.append("current_session_not_excluded")

    # Тот же принцип, что для mcp_servers выше: список без файла-источника -
    # не инвентарь, а пропуск. skills/rules_files_count без источника уходят
    # в отчёт как null, а не как то, что харнесс о себе вспомнил.
    skills_src = disc.get("skills_source")
    skills_source_ok = isinstance(skills_src, dict) and bool(skills_src.get("file"))
    skills_raw = disc.get("skills")
    skills_list = skills_raw if (skills_source_ok and isinstance(skills_raw, list)) else None

    rules_src = disc.get("rules_files_source")
    rules_source_ok = isinstance(rules_src, dict) and bool(rules_src.get("path") or rules_src.get("file"))
    rules_count_raw = disc.get("rules_files_count")
    rules_count = (rules_count_raw if (rules_source_ok and isinstance(rules_count_raw, int))
                   else None)

    meta = build_meta(tz_offset_minutes)
    environment = build_environment(disc, harness_detected_by, harness_version_looks_exact)

    collection_health = build_collection_health(
        discovery_status, diag, rank_dropped, warnings, partial_reasons, days,
        sessions_total=diag["files_listed"], episodes_total=len(episodes) + dropped,
        role_plausibility=role_plausibility, tool_failures_unmeasured=tool_failures_unmeasured,
        human_declines_unmeasured=human_declines_unmeasured, tool_attribution=tool_attribution,
        workaround_wordless_unmeasured=workaround_wordless_unmeasured,
        flat_median_axes=flat_median_axes, mcp_inventory_unmeasured=not mcp_source_ok,
        steps_unmeasured=steps_unmeasured)
    # Та же прозрачность, что и у остальных полей collection_health: видно не
    # только ЧТО посчитано, но и было ли вообще разрешено собирать тексты
    # реплик - отдельно от того, найдены ли повторяющиеся жалобы (это уже
    # решает сам агент по содержимому файла в Части 2, а не эта метрика).
    collection_health["user_messages_saved"] = collect_messages
    profile_full = dict(merged_profile, self_check=self_check)
    profile_share = dict(merged_profile)

    top_anomaly_keys = ("session_prefix", "started_at", "episode_ref", "duration_min",
                         "user_turns", "agent_steps", "short_turns", "max_code_churn",
                         "total_code_edits", "distinct_code_files", "max_scratchpad_churn",
                         "file_type", "silent_recoveries", "visible_failures", "top_tools",
                         "anomaly_score")
    if steps_unmeasured:
        top_anomaly_keys = tuple(k for k in top_anomaly_keys if k != "agent_steps")

    report = {
        "meta": meta,
        "environment": environment,
        "collection_health": collection_health,
        "profile": profile_full,
        "scanned_at": now_iso,
        "harness": {
            "name": disc.get("harness_name"),
            "version": disc.get("harness_version"),
            "os": disc.get("os"),
            "log_format_note": disc.get("log_format_note"),
            "sources_not_analyzed": disc.get("sources_not_analyzed", []),
            "version_looks_exact": version_ok,
            "component_versions": disc.get("component_versions", {}),
        },
        "diagnostics": diag,
        "sessions_analyzed": len(by_sess),
        "episodes_analyzed": len(episodes),
        "episodes_dropped_too_short": dropped,
        "episodes_kept_as_autonomous_loops": kept_autonomous,
        "brag_stats": brag,
        "baseline_medians": medians,
        "baseline_medians_by_file_type": medians_by_file_type,
        "baseline_medians_by_month": medians_by_month,
        "file_type_distribution": file_type_distribution,
        "ranking": {
            "axes_used": rank_used,
            "axes_excluded_as_constant": rank_dropped,
            "axes_low_information": low_info,
            "max_possible_score": len(rank_used),
        },
        "capability_inventory": {
            "native_tools": disc.get("native_tools", []),
            "native_capabilities_claimed": build_native_capabilities(disc.get("native_capabilities_claimed")),
            "plugins_extensions": disc.get("plugins_extensions", []),
            "skills": skills_list,
            "skills_source": skills_src if skills_source_ok else None,
            "memory_mechanisms": build_memory_mechanisms(disc.get("memory_mechanisms"), usage, mcp_direct),
            "rules_files_count": rules_count,
            "rules_files_source": rules_src if rules_source_ok else None,
        },
        "mcp_inventory": ({
            "declared_servers": declared,
            "declared_servers_source": mcp_src,
            "usage_breakdown": usage,
            "dead_weight_servers": [s for s, c in usage.items() if c == 0],
            "unattributed_namespaces": unattributed,
            "dispatcher_calls_by_server": dict(mcp_direct),
            "undeclared_servers_used": undeclared_used,
        } if mcp_source_ok else {
            "declared_servers": None,
            "declared_servers_source": None,
            "usage_breakdown": None,
            # dead_weight_servers и undeclared_servers_used опущены целиком -
            # без подтверждённого источника конфига "мёртвый груз" не посчитан,
            # а не посчитан нулём (см. docs/decisions.md, находка про
            # выдуманный инвентарь MCP: ноль тоже был бы неправдой).
            "unattributed_namespaces": unattributed,
            "dispatcher_calls_by_server": dict(mcp_direct),
        }),
        "tool_usage_global": {name: {"calls": c, "failures": tool_failures.get(name, 0),
                                     "human_declines": tool_human_declines.get(name, 0)}
                              for name, c in tool_global.most_common(25)},
        "silent_workarounds": silent_workarounds,
        # Вся находка построена на agent_steps/steps_per_user_turn - без
        # steps_unmeasured==False null целиком, а не с обнулёнными полями
        # внутри: пустой top/episodes_selected читался бы как "автономных
        # эпизодов не было", а не как "не измеряли" (см. docs/decisions.md).
        "invisible_inefficiency": (None if steps_unmeasured else {
            "note": ("Агент много работает при малом участии человека. Высокое "
                     "steps_per_user_turn - признак, что задача шла вхолостую, "
                     "а человек об этом не знал."),
            "median_steps_per_user_turn": medians["steps_per_user_turn"]["median"],
            "selection_rule": (f"agent_steps >= {MIN_STEPS_FOR_INVISIBLE} и "
                               f"steps_per_user_turn >= {round(ratio_cut, 1)} "
                               f"({INVISIBLE_RATIO_FACTOR}x медианы), сортировка по числу шагов"),
            "episodes_selected": len(invisible),
            "share_of_all_episodes": round(len(invisible) / len(episodes), 3),
            "top": [
                {k: e[k] for k in ("session_prefix", "started_at", "episode_ref",
                                   "steps_per_user_turn", "agent_steps", "user_turns",
                                   "duration_min", "silent_recoveries",
                                   "max_code_churn", "total_code_edits", "distinct_code_files",
                                   "file_type", "top_tools")}
                for e in invisible[:5]
            ],
        }),
        "top_anomalies_anonymized": [
            {k: e[k] for k in top_anomaly_keys}
            for e in episodes[:5]
        ],
    }

    # Два эпизода одной сессии делят один session_prefix (см. measure()) -
    # started_at рядом с ним и episode_ref для цитирования человеку должны
    # уже различать их (см. docs/decisions.md), но если где-то в будущем это
    # снова сломается, отчёт не должен из-за этого упасть на чужой машине:
    # конфликт разводится автоматически, а факт остаётся только в diagnostics
    # (человек этого не видит, см. Часть 4/5 промта). Жёсткая проверка того же
    # самого - в tools/check_episode_ids.py, она запускается у нас, не у него.
    diag["episode_id_conflicts"] = _dedupe_episode_ids(
        report["top_anomalies_anonymized"],
        (report["invisible_inefficiency"]["top"] if report["invisible_inefficiency"] else []))

    # Локальная выгрузка реплик человека: нужна для поиска ПОВТОРЯЮЩИХСЯ проблем,
    # которые статистика эпизодов не видит (одна и та же мелочь в двадцати задачах
    # не даёт выброса ни по одной оси). Файл НЕ для отправки: он содержит тексты.
    # Пишется, только если человек разрешил это вопросом в начале Шага 1
    # (collect_messages) - без разрешения all_user_msgs всё равно посчитан
    # (он уже отработал в brag_stats выше по main()), просто не попадает на
    # диск текстом.
    all_user_msgs.sort(key=lambda x: x[1])
    msgs_path = None
    if collect_messages:
        msgs_path = Path("audit_user_messages.txt").resolve()
        with open(msgs_path, "w", encoding="utf-8") as f:
            for sid, ts, txt, _ln in all_user_msgs:
                f.write(f"{sid[:8]}\t{ts.date().isoformat()}\t{txt}\n")

    out = Path("workspace_audit_report.json").resolve()
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # Отдельный файл для обмена. Из полного отчёта убрано всё, что может выдать
    # устройство машины: описание формата логов, список неразобранных источников
    # с путями, идентификаторы сессий. Остаются только числа и названия продуктов.
    def strip_ids(lst):
        return [{k: v for k, v in e.items()
                 if k not in ("session_prefix", "started_at", "episode_ref")}
                for e in lst]

    share = {
        "meta": meta,
        "environment": environment,
        "collection_health": collection_health,
        "profile": profile_share,
        "scanned_at": report["scanned_at"],
        "harness": {k: report["harness"][k] for k in
                    ("name", "version", "os", "version_looks_exact", "component_versions")},
        "sessions_analyzed": report["sessions_analyzed"],
        "episodes_analyzed": report["episodes_analyzed"],
        "episodes_dropped_too_short": report["episodes_dropped_too_short"],
        "episodes_kept_as_autonomous_loops": report["episodes_kept_as_autonomous_loops"],
        "brag_stats": report["brag_stats"],
        "baseline_medians": report["baseline_medians"],
        "baseline_medians_by_file_type": report["baseline_medians_by_file_type"],
        "baseline_medians_by_month": report["baseline_medians_by_month"],
        "file_type_distribution": report["file_type_distribution"],
        "ranking": report["ranking"],
        # Структура вместо прозы: код возможности и разобранные поля памяти
        # (name/transport/local/calls) уходят наружу, свободное description -
        # только в report["capability_inventory"] на машине человека.
        # skills_source/rules_files_source/declared_servers_source (ниже) несут
        # путь к файлу конфигурации на диске человека - ровно то, что share не
        # должен отдавать наружу. Наружу идёт только их СЛЕДСТВИЕ: skills,
        # rules_files_count и declared_servers равны null, если источника не
        # было, и заполнены, если был - этого достаточно, сам путь получателю
        # не нужен (см. docs/decisions.md).
        "capability_inventory": {
            "native_tools": report["capability_inventory"]["native_tools"],
            "native_capabilities_claimed": [
                c["code"] for c in report["capability_inventory"]["native_capabilities_claimed"]
                if c.get("code")
            ],
            "plugins_extensions": report["capability_inventory"]["plugins_extensions"],
            "skills": report["capability_inventory"]["skills"],
            "memory_mechanisms": [
                {k: v for k, v in m.items() if k != "description"}
                for m in report["capability_inventory"]["memory_mechanisms"]
            ],
            "rules_files_count": report["capability_inventory"]["rules_files_count"],
        },
        "mcp_inventory": {k: v for k, v in report["mcp_inventory"].items()
                          if k != "declared_servers_source"},
        "tool_usage_global": report["tool_usage_global"],
        # examples вырезаны - там session_prefix и время конкретного эпизода;
        # наружу идут только числа и имена инструментов (top_pairs).
        "silent_workarounds": silent_workarounds_share,
        # selection_rule - константа для всех при одном metric_version, места
        # не несёт информации о конкретном человеке и шумит в grep-проверке.
        "invisible_inefficiency": (None if report["invisible_inefficiency"] is None else {
            "episodes_selected": report["invisible_inefficiency"]["episodes_selected"],
            "top": strip_ids(report["invisible_inefficiency"]["top"]),
        }),
        "top_anomalies": strip_ids(report["top_anomalies_anonymized"]),
        "diagnostics": {k: v for k, v in report["diagnostics"].items()
                        if k != "error_value_samples"},
    }
    share_path = Path("audit_share.json").resolve()
    share_path.write_text(json.dumps(share, ensure_ascii=False, indent=2), encoding="utf-8")

    append_state(state_path, {"type": "run", "run_seq": run_seq, "at": now_iso,
                               "schema_version": SCHEMA_VERSION,
                               "metric_version": METRIC_VERSION, "status": discovery_status})

    print("\n--- АУДИТ ЗАВЕРШЁН ---")
    print(f"Контрольная сумма исполняемого кода (SHA-256, без переносов строк): "
          f"{code_checksum}")
    print("Сверь её с суммой, указанной в промте рядом с кодом Шага 2 - не совпадает, "
          "значит этот прогон посчитан не каноническим скриптом, а его пересказом.")
    print(f"Харнесс: {report['harness']['name']} {report['harness']['version'] or ''}")
    print(f"Сессий: {len(by_sess)} | Эпизодов: {len(episodes)} | Коротких отброшено: {dropped}"
          + (f" | Сохранено автономных петель: {kept_autonomous}" if kept_autonomous else ""))
    print(f"Медиана правок одного файла: {medians['max_code_churn']['median']} "
          f"(p75 {medians['max_code_churn']['p75']}, макс {medians['max_code_churn']['max']}) | "
          f"Медиана длительности: {medians['duration_min']['median']} мин")
    w = brag["when_you_work"]
    print(f"Ритм: пик активности в {w['peak_hour_local']}:00, "
          f"ночью (00-06) {w['night_share_00_06']*100:.0f}%, "
          f"по выходным {w['weekend_share']*100:.0f}%"
          + ("" if tz_known else "  [часовой пояс не указан, считалось по UTC]"))
    print(f"Стаж: {brag['active_days']} активных дней, {brag['hours_with_agent']} ч с агентом, "
          f"{brag['tasks_completed']} задач, {brag['characters_typed']:,} символов написано")
    if steps_unmeasured:
        print("ВНИМАНИЕ: step_classification_basis не заполнен в discovery — метрики по числу "
              "шагов агента (agent_steps, steps_per_user_turn, автономные эпизоды) не посчитаны "
              "вовсе: без объявленного разделения строк лога на действия агента и служебную "
              "телеметрию харнесса эти числа были бы завышены.")
    elif diag["service_lines_excluded"]:
        print(f"Служебных строк лога (не действий агента) исключено из счёта: "
              f"{diag['service_lines_excluded']}.")
    if mcp_source_ok:
        print(f"MCP заявлено: {len(declared)} | Мёртвый груз: "
              f"{len(report['mcp_inventory']['dead_weight_servers'])}")
    else:
        print("MCP: файл-источник конфигурации не найден (mcp_servers_source) — "
              "инвентарь не подтверждён, «мёртвый груз» не посчитан.")
    if diag["skipped_audit_marker"]:
        print(f"Из разбора исключено {diag['skipped_audit_marker']} прошлых сессий, где аудит "
              f"реально запускали (не эта сессия — более ранние).")
    if not role_ok:
        print(f"ВНИМАНИЕ (главное): {role_reason} Числа в этом отчёте, вероятно, недостоверны — "
              f"проверь field_map.role/user_role_value в discovery, прежде чем доверять остальному.")
    if invisible:
        w = invisible[0]
        print(f"Автономная работа: норма {medians['steps_per_user_turn']['median']} действий на реплику; "
              f"{len(invisible)} эпизодов выше {round(ratio_cut, 1)}. Самый крупный: "
              f"{w['agent_steps']} шагов на {w['user_turns']} реплик за {w['duration_min']} мин "
              f"({w['steps_per_user_turn']} на реплику)")
    if silent_workarounds["total"] and not tool_failures_unmeasured:
        # Составляем находку из того, что реально измерено, а не по одному
        # фиксированному шаблону: каждая часть добавляется своим условием, а
        # не печатается всегда с подстановкой значения по умолчанию.
        parts = [f"{silent_workarounds['total']} из {silent_workarounds['tool_failures_total']} "
                 f"отказов инструмента агент сразу обошёл другим способом, не спросив"]
        if not workaround_wordless_unmeasured:
            parts.append(f"{silent_workarounds['wordless_total']} из них — вообще без единого слова")
        if silent_workarounds["top_pairs"]:
            top = silent_workarounds["top_pairs"][0]
            parts.append(f"чаще всего вместо {top['from_tool']} — {top['to_tool']} "
                         f"({top['count']} раз)")
        if "longest_chain_calls" in silent_workarounds:
            parts.append(f"самая длинная цепочка — {silent_workarounds['longest_chain_calls']} "
                         f"вызовов за {silent_workarounds['longest_chain_duration_min']} мин")
        print("Тихие обходы: " + "; ".join(parts) + ".")
    if workaround_wordless_unmeasured and silent_workarounds["total"] and not tool_failures_unmeasured:
        print(f"ВНИМАНИЕ: признак ошибки в этом формате логов стоит почти на каждой строке (не "
              f"только на результатах вызовов) — отличить «агент промолчал» от «агент написал "
              f"текст» этот формат не позволяет. silent_workarounds.wordless_total не измерен, "
              f"остальные числа обхода (сколько, самая длинная цепочка, частые пары) верны.")
    if rank_dropped:
        print(f"ВНИМАНИЕ: оси {rank_dropped} одинаковы во всех эпизодах и исключены из "
              f"ранжирования. Балл теперь из {len(rank_used)} осей (максимум {len(rank_used)}.0).")
    if tool_failures_unmeasured:
        print(f"ВНИМАНИЕ: у всех {len(tool_global)} инструментов отказов ровно 0 за весь период — "
              f"похоже, признак ошибки в этом формате логов не измерен, а не что сбоев не было.")
    if diag["unresolved_tool_failures"]:
        print(f"ВНИМАНИЕ: {diag['unresolved_tool_failures']} отказов зафиксировано, но не "
              f"привязано ни к одному инструменту (нет общего id и нет вызова поблизости) — "
              f"доля отказов по конкретным инструментам в tool_usage_global занижена.")
    if human_declines_unmeasured:
        print(f"ВНИМАНИЕ: харнесс не объявил human_decline_values — отказ человека (не разрешил "
              f"действие) и отказ инструмента в этом формате логов неразличимы. "
              f"tool_usage_global.human_declines не измерен, вся эта часть отказов осела в failures.")
    if tool_attribution["per_tool_counts_approximate"]:
        print(f"ВНИМАНИЕ: {tool_attribution['by_adjacency']} из "
              f"{tool_attribution['by_adjacency'] + tool_attribution['by_id'] + tool_attribution['by_same_row']} "
              f"отказов привязаны к инструменту по соседству строк, а не по общему id — разбивка "
              f"отказов по конкретным инструментам приблизительная (общее число отказов точное).")
    if not version_ok:
        print(f"ВНИМАНИЕ: версия харнесса записана как '{hv or 'не указана'}' — это похоже "
              f"на маркетинговое обозначение, а не на точный номер сборки. Без него нельзя "
              f"будет сравнить, что закрывается нативно в разных версиях.")
    if low_info:
        print(f"ВНИМАНИЕ: оси {list(low_info)} почти не различают эпизоды "
              f"(одно значение у >=90% из них) — не трактуй их как содержательный результат.")
    if diag["user_turns_total"] > 20 and diag["short_user_turns_total"] == 0:
        print("ВНИМАНИЕ: коротких реплик человека не найдено ни одной. Вероятно, к тексту "
              "реплик приклеен служебный хвост — укажи его в field_map.content_strip_patterns.")
    if undeclared_used:
        print(f"ВНИМАНИЕ: вызываются серверы, которых нет в mcp_servers: "
              f"{list(undeclared_used)}. Вердикт 'мёртвый груз' может быть ошибочным — "
              f"проверь, не тот ли это сервер под другим именем.")
    if diag["ambiguous_error_values"]:
        print(f"ВНИМАНИЕ: у {diag['ambiguous_error_values']} событий поле is_error содержит "
              f"нераспознанный статус {diag['error_value_samples']} — они НЕ считаны как ошибки. "
              f"Проверь field_map.is_error.")
    if diag["events_total"] and diag["events_with_file_path"] == 0:
        print("ВНИМАНИЕ: ни у одного события не извлечён путь к файлу — churn будет 0. "
              "Проверь field_map.tool_args_path.")
    if diag["files_missing"] or diag["unrecognized_schema"]:
        print(f"ВНИМАНИЕ: файлов не найдено {diag['files_missing']}, "
              f"схема не распознана у {diag['unrecognized_schema']} — они НЕ учтены.")
    print("\nФайлы:")
    print(f"  [приватно]  {out}")
    print("              полный отчёт, остаётся на этой машине")
    if collect_messages:
        print(f"  [приватно]  {msgs_path}")
        print(f"              {len(all_user_msgs)} реплик для поиска повторов, никуда не отправляется")
    else:
        print("  (audit_user_messages.txt не создан - человек не разрешил в начале Шага 1;")
        print("   находка про повторяющиеся жалобы и просьбы в Части 2 недоступна, остальное посчитано)")
    print(f"  [приватно]  {state_path}")
    print("              install_id и история прогонов; не для отправки")
    print(f"  [МОЖНО ПОДЕЛИТЬСЯ]  {share_path}")
    print("              только числа и названия инструментов: ни путей, ни текстов,")
    print("              ни идентификаторов сессий. Загляни в него перед отправкой —")
    print("              названия своих скиллов ты узнаешь сам.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
