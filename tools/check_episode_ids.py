#!/usr/bin/env python3
"""
Юнит-тест на _dedupe_episode_ids из audit_core.py - механизм, который
разводит конфликтующие идентификаторы эпизодов (session_prefix, started_at)
вместо того, чтобы ронять прогон у человека (см. docs/decisions.md).

Это ЖЁСТКАЯ проверка (падает при неверном поведении) - в отличие от самого
audit_core.py, который на конфликте молча чинит и не падает никогда. Разница
сознательная: в audit_core.py падение на чужой машине - потерянный
пользователь; здесь, у нас, если механизм починки сломается, лучше упасть
сразу и громко, чем узнать об этом от кого-то другого через месяц.

Проверяет три случая:
  1. Разные эпизоды (разный (session_prefix, started_at)) - конфликтов нет,
     записи не тронуты.
  2. Один и тот же (session_prefix, started_at) с РАЗНЫМИ числами - это и есть
     баг (session_prefix перепутан с id эпизода); дедупликация обязана его
     развести и сообщить о находке.
  3. Один и тот же (session_prefix, started_at) с ОДИНАКОВЫМИ числами - один
     и тот же эпизод законно попал в оба списка (top_anomalies и
     invisible_inefficiency могут пересекаться) - это не конфликт, трогать
     запись не нужно.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit_core import _dedupe_episode_ids  # noqa: E402


def make_episode(session_prefix, started_at, duration_min, agent_steps, user_turns):
    return {
        "session_prefix": session_prefix,
        "started_at": started_at,
        "episode_ref": f"{session_prefix} ref",
        "duration_min": duration_min,
        "agent_steps": agent_steps,
        "user_turns": user_turns,
    }


def check_no_conflict():
    a = make_episode("aaaaaaaa", "2026-01-01T00:00:00+00:00", 10.0, 20, 3)
    b = make_episode("bbbbbbbb", "2026-01-02T00:00:00+00:00", 40.0, 80, 5)
    conflicts = _dedupe_episode_ids([a], [b])
    if conflicts != 0:
        print(f"ПРОВАЛ [нет конфликта]: ожидалось 0 конфликтов, получено {conflicts}.")
        return False
    if a["session_prefix"] != "aaaaaaaa" or b["session_prefix"] != "bbbbbbbb":
        print("ПРОВАЛ [нет конфликта]: записи без конфликта не должны меняться.")
        return False
    print("OK: разные эпизоды - конфликтов нет, записи не тронуты.")
    return True


def check_real_conflict():
    # Тот самый баг: одна сессия, два разных эпизода, один и тот же
    # session_prefix и (по несчастливой случайности) один и тот же started_at.
    a = make_episode("89b376d9", "2026-08-29T08:27:21+00:00", 150.0, 806, 30)
    b = make_episode("89b376d9", "2026-08-29T08:27:21+00:00", 40.0, 1200, 6)
    conflicts = _dedupe_episode_ids([a], [b])
    if conflicts != 1:
        print(f"ПРОВАЛ [реальный конфликт]: ожидался 1 конфликт, получено {conflicts}.")
        return False
    if a["session_prefix"] == b["session_prefix"]:
        print("ПРОВАЛ [реальный конфликт]: session_prefix не разведён после дедупликации.")
        return False
    if a["episode_ref"] == b["episode_ref"]:
        print("ПРОВАЛ [реальный конфликт]: episode_ref не разведён после дедупликации.")
        return False
    print(f"OK: конфликт найден и разведён ({a['session_prefix']!r} vs {b['session_prefix']!r}).")
    return True


def check_legit_overlap():
    # Один и тот же эпизод законно попал в top_anomalies И invisible_inefficiency.
    a = make_episode("cccccccc", "2026-03-03T00:00:00+00:00", 90.0, 500, 4)
    b = make_episode("cccccccc", "2026-03-03T00:00:00+00:00", 90.0, 500, 4)
    conflicts = _dedupe_episode_ids([a], [b])
    if conflicts != 0:
        print(f"ПРОВАЛ [законное пересечение]: одинаковые числа не конфликт, "
              f"а получено {conflicts}.")
        return False
    if a["session_prefix"] != b["session_prefix"]:
        print("ПРОВАЛ [законное пересечение]: запись без конфликта не должна меняться.")
        return False
    print("OK: один и тот же эпизод в двух списках с одинаковыми числами - не конфликт.")
    return True


def main():
    ok = check_no_conflict()
    ok = check_real_conflict() and ok
    ok = check_legit_overlap() and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
