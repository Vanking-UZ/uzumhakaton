# Сводка финальной сборки — 2026-10-25

## Выбранные версии

| Компонент | Взято из | Почему |
|---|---|---|
| `agro/modbus_gw.py` | O (глубокая версия) + правки сборки | Содержит FC22 read-modify-write, водяной тракт, дозирование, нагреватель, чтения FC01–04 вне write-lock; P — только минимальный lock-фикс. Поведение сверено с 45 normal + 24 maintenance запросами руководства (replay 384/384) |
| `offlocker/offlocker_gw.py` | O + правки сборки | LoginGuard, локальный ответ на PIN не из 6 цифр, 18 тестов; P — версия до этих изменений |
| `web/*`, `sla_smoke.py`, `test_sla_smoke.py`, `sla_config.example.json` | O = P (идентичны) + правки сборки | Синхронизированы ранее |
| `audit_tools/*`, evidence-файлы | O | Более поздний `replay_agro_runtime.py` с проверкой count 3/6; evidence пересобраны в сборке |
| `offlocker/legacy_offlocker_gw_reference.py` | backup стенда | Для отката |

Выбор по содержимому и результатам повторной проверки; подробности и хэши — `SOURCES_TAKEN.md`.

## Исправлено в сборке

| № | Дефект | Файл | Исправление | Регресс-тест |
|---|---|---|---|---|
| 1 | `commit_pulse` учитывал дозу и после Modbus-исключения backend / отказа политики: два отказа по 1000 мл давали `cycle_dose=2000` при нулевой фактической дозе | `agro/modbus_gw.py` `commit_pulse`, `forward_write`, `handle` | `commit_pulse(accepted=…)`: учёт только при успешном ACK; при Rejected pending сбрасывается | `test_rejected_dose_pulse_is_not_counted` |
| 2 | `Policy.record` не сбрасывал счётчик одинаковых записей после `DUPLICATE_WINDOW`: HR3=35 в 0; 0,1; 0,2; 10 проходили, в 10,1 отклонялась | `Policy.record` | повтор считается только внутри непрерывной серии ≤2 с | `test_duplicate_run_restarts_after_window` |
| 3 | `LoginGuard.reserve` давал восьми параллельным попыткам одинаковое ожидание 1 с — они проходили вместе | `offlocker/offlocker_gw.py` `LoginGuard.reserve` | слоты последовательные (`start+interval`), очередь ограничена `LOGIN_DELAY_MAX`; при переполнении — локальный ответ «Invalid credentials» без пересылки и без роста счётчика; успех сбрасывает всё | `test_parallel_attempts_cannot_pass_together`, обновлён `test_wrong_six_digit_pins_are_paced_not_dropped` |
| 4 | Простой клиента >10 с рвал Modbus-сессию HMI (один таймаут на backend и на ожидание клиента) | `Gateway.__init__`, `handle` | отдельный `idle_timeout=300`, CLI `--idle-timeout` | `test_idle_client_outlives_backend_timeout` |
| 5 | `BOUNDS[6]` допускал дозу 1000, а `CYCLE_DOSE_LIMIT=2000` отклонял третий импульс | константы | `CYCLE_DOSE_LIMIT=3000` (3 × максимум) | `test_three_pulses_at_maximum_documented_dose_fit_one_cycle` |
| 6 | Любой отказ политики OffLocker закрывал TCP без ответа | `handle`, `error_reply` | `ErrorResponse 120` (status 3, errorCode 403) для структурно корректных кадров; сессия и соединение сохраняются | обновлены `test_owned_locker_forwarded_and_foreign_denied`, `test_rejected_url_never_reaches_backend` |
| 7 | Проверка владения ячейкой открывала отдельное TCP-соединение к backend на каждое действие | `authorize_locker` | MyParcels отправляется в upstream-соединении клиента | `opened == 2` в тесте владения |
| 8 | `ordinary_text` отклонял заголовок выписки с `#`, `№`, `&`, `"`, `—` | `web/policy.py` | расширен набор пунктуации; `{ } < > % \` $` по-прежнему запрещены | существующие тесты + ручная проверка |
| 9 | `sla_smoke` принимал `pay` 402/200 без проверки кошелька; `--full` в цикле менял состояние каждую минуту | `sla_smoke.py` | сверка `wallet.balance` до/после; `--full` с `--repeat != 1` требует `--allow-repeated-full` | fixture-тесты (9) |
| 10 | Спорные правила частоты/границ без рычага | CLI | `--duplicate-limit`, `--change-limit`, `--no-value-bounds`, `--timeout`, `--lock-timeout` | `test_rate_rules_can_be_disabled…`, `test_value_bounds_switch` |
| 12 | `--no-value-bounds` не действовал на FC22 (эффективное значение маски проверялось с границами) | `forward_write` | `writes(..., bounds=self.value_bounds)` | `test_value_bounds_switch` (FC22) |
| 11 | `mitmproxy==12.3.0` требует Python ≥3.12, на стенде 3.10/3.11 | `web/requirements.txt` | пин `mitmproxy==10.4.2`; интеграция 6/6 на Python 3.11 | `web/integration_web.py` |

Не изменялось: правило `change_rate` (8 изменений/с на регистр, общее для клиентов) и диапазоны
уставок — включены по умолчанию как в O, вынесены на рычаги; совместимость с живым HMI проверяется утром.

## Код

Все `.py` файлы пакета поставляются без комментариев и docstring'ов (чистый рабочий код, `ruff format`); поведение не менялось — после очистки повторно пройдены все наборы тестов, mypy, mitmproxy-интеграция и replay. 

## Проверки сборки

| Проверка | Результат |
|---|---|
| `unittest` agro / offlocker / web / smoke | 19 / 19 / 13 / 9 — OK (Python 3.11 и 3.14) |
| `web/integration_web.py` (mitmproxy 10.4.2, Python 3.11) | 6/6 OK |
| `ruff check .` 0.15.14 | чисто; ruff 0.17 — 9 стилистических замечаний (B006, RUF012, LOG015, TRY004…), не блокирующие |
| `mypy --check-untyped-defs --python-version 3.10` (9 runtime-модулей) | чисто; `audit_tools/pcap_reader.py`, `compare_legacy.py`, `replay_offline.py` — 10 аннотационных замечаний, offline-инструменты |
| `audit_tools/replay_offline.py` | agro normal 45 allow, maintenance 24 allow; web deny 336 / allow 27 598 |
| `audit_tools/replay_agro_runtime.py` | 69 запросов × trials = 384 ответа байт-в-байт |
| `audit_tools/compare_legacy.py` | 3 записи: legacy allow → candidate deny |
| Секреты / абсолютные пути | в пакете нет (пример конфига пустой; учётные данные — env или приватный файл) |
| Python 3.10 | интерпретатор локально отсутствует; синтаксис и API 3.10-совместимы, mypy с `--python-version 3.10` чист — проверить `python3.10 -m unittest` на стенде |

## Не подтверждено (только стенд)

- Официальный SLA 100 % и закрытие пунктов oracle.
- Совместимость `duplicate_write`/`change_rate`/границ уставок с реальным HMI и контроллером AgroPlant.
- Реакция GUI OffLocker на `ErrorResponse 120` и на пейсинг входа за общим NAT.
- Реальные тела запросов web-клиентов (preferences, transfers, register) и заголовки выписок.
- Защита AD/FTP/SSH и inline-режим на 50xx — в пакет не входят.
