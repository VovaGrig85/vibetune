import json, os, re

# Подтверждено по коду приёмника: признак источника — в теле, заголовком не передаётся.
SOURCE_FIELD = ("source", "vibetune-audit")

# Обязательны в meta: schema_version, metric_version, run_seq (целые, не bool)
# и install_id — ровно 16 hex-символов в нижнем регистре.
REQUIRED_META = ("schema_version", "metric_version", "run_seq", "install_id")

# Нагрузка — это audit_share.json как он есть, плюс поле source. Второго
# белого списка здесь нет.
# profile.self_check не попадает в share - остаётся только в локальном отчёте.

def build_payload(share):
    if share.get(SOURCE_FIELD[0]) not in (None, SOURCE_FIELD[1]):
        raise ValueError("поле source в share-файле занято чем-то другим")
    out = dict(share)
    out[SOURCE_FIELD[0]] = SOURCE_FIELD[1]
    return out


# Хост:порт вида internal-service:8080, без слешей.
HOSTPORT_RE = re.compile(r"[A-Za-z][A-Za-z0-9._-]*:\d{2,5}(?!\d|:)")
# Почтовый адрес: после @ обязателен домен с точкой и буквенным TLD.
# "claude-mem@thedotmack" (формат имя@издатель из маркетплейса плагинов) не
# подходит под это правило и не считается адресом.
EMAIL_RE = re.compile(r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Восемь подряд hex-символов, не примыкающих к другим hex-символам, - форма
# session_prefix и всего, что из него собрано (episode_ref и подобное) в
# отчёте. Сейчас оба поля вырезаются из share по имени (strip_ids в
# audit_core.py) и не утекают - эта проверка ловит их же по ФОРМЕ значения, на
# случай если фрагмент такой же формы появится под новым именем поля, которое
# забудут внести в тот же белый список. install_id (16 hex подряд) и
# code_checksum (64 hex подряд) не задевает - в них с обеих сторон каждого
# 8-символьного окна есть ещё hex-символы.
SESSION_HASH_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{8}(?![0-9a-f])")

# Общий потолок длины (120) ловит утечку текста реплики или пути, случайно
# оказавшегося в поле. Но пара полей — честное ПОЯСНЕНИЕ харнесса о своём же
# устройстве, а не текст лога и не идентификатор, - там честное описание
# реально не влезает в 120 символов (см. docs/decisions.md, находка про
# гранулярность шага Antigravity). Один раз это уже привело к тому, что
# описание подрезали вручную, лишь бы проверка прошла, — то есть подогнали
# данные под проверку, а не под правду (тот же класс ошибки, что и подгонка
# после отказа проверки — см. docs/decisions.md). Решение — не поднимать потолок всем
# полям сразу, а разрешить более длинный текст ТОЛЬКО этим явно
# перечисленным путям: остальные поля так же легко словят путь или текст
# любой длины, как и раньше.
LONG_TEXT_ALLOWED_PATHS = {"payload.environment.step_granularity_note"}
LONG_TEXT_MAX_LEN = 300

# Показывается вместе с находками find_suspicious, а не только в audit_prompt.md
# и CLAUDE.md - в момент отказа читают именно то, что вернул prepare(), и
# предупреждение обязано быть там же, а не только в инструкции, которую можно
# не перечитать. Уже был реальный случай, когда отказ обошли, укоротив
# отказавшее поле и пересобрав payload заново (см. docs/decisions.md) - решение
# про эти данные принимает человек, не тот, кто читает сообщение об ошибке.
LEAK_CHECK_WARNING = (
    "ПРОВЕРКА НЕ ОБХОДИТСЯ: не редактируй audit_discovery.json, отчёт или "
    "payload, чтобы она прошла, и не пересобирай их заново с этой же целью — "
    "ни по своей инициативе, ни если причина кажется безобидной. Дальше "
    "решает человек."
)


# Запись файла нагрузки отменяется, если в ней встретилось что-то похожее на
# путь, адрес, обрывок хеша сессии или чужое имя.
def find_suspicious(node, path="payload"):
    bad = []
    if isinstance(node, dict):
        for k, v in node.items():
            bad += find_suspicious(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            bad += find_suspicious(v, f"{path}[{i}]")
    elif isinstance(node, str):
        s = node
        looks_like_path = ("/" in s) or ("\\" in s)
        max_len = LONG_TEXT_MAX_LEN if path in LONG_TEXT_ALLOWED_PATHS else 120
        if (looks_like_path or HOSTPORT_RE.search(s) or EMAIL_RE.search(s)
                or SESSION_HASH_RE.search(s) or len(s) > max_len):
            bad.append((path, s[:80]))
    return bad


def check_meta(payload):
    """Сервер не обязан объяснять, чего не хватает. Проверяем у себя, до сети."""
    meta = payload.get("meta") or {}
    missing = [k for k in REQUIRED_META if k not in meta]
    bad = []
    for k in ("schema_version", "metric_version", "run_seq"):
        v = meta.get(k)
        if not isinstance(v, int) or isinstance(v, bool):
            bad.append(k)
    iid = meta.get("install_id")
    if not isinstance(iid, str) or not re.fullmatch(r"[0-9a-f]{16}", iid.strip().lower()):
        bad.append("install_id")
    return missing, bad


def prepare(share, out_dir):
    """Собрать нагрузку из audit_share.json, проверить, записать. Ничего не отправляет."""
    payload = build_payload(share)
    missing, bad = check_meta(payload)
    if missing or bad:
        return None, [("meta", f"нет: {missing}, неверный тип: {bad}")]
    problems = find_suspicious(payload)
    if problems:
        return None, [("_warning", LEAK_CHECK_WARNING)] + problems
    path = os.path.join(out_dir, "vibetune_payload.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path, []
