# Происхождение файлов финального пакета

O = рабочая копия A, P = рабочая копия B.
Снимок источников: snapshot 02:41:47; повторная сверка 03:02 — оба источника не изменились. Полные хэши источников — `hashes_src_O.txt`, `hashes_src_P.txt` в каталоге сборки.

| Файл | Источник | SHA-256 в пакете | SHA-256 в O | SHA-256 в P |
|---|---|---|---|---|
| `BUILD_SUMMARY_RU.md` | создан в сборке | `8573581f92fda19e` | `-` | `-` |
| `agro/incident_phases.json` | O (без изменений) | `35cd9d91fdce11f7` | `35cd9d91fdce11f7` | `35cd9d91fdce11f7` |
| `agro/modbus_gw.py` | O + правки сборки | `0a6449d8c445ebd0` | `833df8656bf332a7` | `7981345b585150dd` |
| `agro/protocol_evidence.json` | O (без изменений) | `08b2cd8dc1a8717e` | `08b2cd8dc1a8717e` | `08b2cd8dc1a8717e` |
| `agro/runtime_capture_replay.json` | O (без изменений) | `d738f668c57cca25` | `d738f668c57cca25` | `fe951fb6be5d8449` |
| `agro/scenarios.json` | O (без изменений) | `03bc1ddc3055e21a` | `03bc1ddc3055e21a` | `03bc1ddc3055e21a` |
| `agro/test_modbus.py` | O + правки сборки (P идентичен O) | `b3df7015771cb29f` | `834075b68a4c94a0` | `834075b68a4c94a0` |
| `audit_findings.csv` | O (без изменений) | `34fb21f75c705b82` | `34fb21f75c705b82` | `5aa7a530d2a7564a` |
| `audit_findings.json` | O (без изменений) | `ccb5aafa9cfcc147` | `ccb5aafa9cfcc147` | `c48eefb5100896d8` |
| `audit_tools/agro_trace.py` | O (без изменений) | `6ef71aa755d5ce86` | `6ef71aa755d5ce86` | `6ef71aa755d5ce86` |
| `audit_tools/compare_legacy.py` | O (без изменений) | `e0839f221d4a83af` | `e0839f221d4a83af` | `e0839f221d4a83af` |
| `audit_tools/pcap_reader.py` | O + правки сборки (P идентичен O) | `0fb6c8fcb82b1115` | `d0903a74bb96e35f` | `d0903a74bb96e35f` |
| `audit_tools/replay_agro_runtime.py` | O + правки сборки | `532c2092601e67f6` | `368bc62bb71767da` | `0ce2b40f3ec4b6e8` |
| `audit_tools/replay_offline.py` | O + правки сборки (P идентичен O) | `931c0f6ff7f37d41` | `9215905fce9f5971` | `9215905fce9f5971` |
| `evidence_count.json` | O (без изменений) | `2e4afccc2e68a589` | `2e4afccc2e68a589` | `2e4afccc2e68a589` |
| `history/AUDIT_REPORT_RU_2026-10-25_0139.txt` | O (перемещён в history/) | `72445e65b4f94cbc` | `-` | `-` |
| `history/verification_2026-10-25_0205.json` | O (перемещён в history/) | `96222518b4c2b961` | `-` | `-` |
| `large_pcap_sweep.json` | O (без изменений) | `c85e03aa91defcaa` | `c85e03aa91defcaa` | `c85e03aa91defcaa` |
| `legacy_comparison.json` | O (без изменений) | `9b0f6959d3de7428` | `9b0f6959d3de7428` | `9b0f6959d3de7428` |
| `market_business_evidence.json` | O (без изменений) | `461d0518340e7f1f` | `461d0518340e7f1f` | `461d0518340e7f1f` |
| `offline_evidence.csv` | O (без изменений) | `6f0b87ab7fb57b4c` | `6f0b87ab7fb57b4c` | `b19f0071b0905f32` |
| `offline_evidence.json` | O (без изменений) | `fc4474257c9e9df3` | `fc4474257c9e9df3` | `40d932b1d157da34` |
| `offlocker/legacy_offlocker_gw_reference.py` | создан в сборке | `b47b926305b14af8` | `-` | `-` |
| `offlocker/offlocker_gw.py` | O + правки сборки | `eccd6f7369ab945d` | `10273f6e64ee4903` | `99e05bcec7dbdad0` |
| `offlocker/test_gateway.py` | O + правки сборки | `5c359759a592a032` | `3e5263d7d902c3d0` | `a9f427266b2cc5f3` |
| `offlocker_capture_summary.json` | O (без изменений) | `bd6c445494d1811f` | `bd6c445494d1811f` | `bd6c445494d1811f` |
| `requirements-dev.txt` | создан в сборке | `bdfa012a8aaab7cc` | `-` | `-` |
| `sla_config.example.json` | O (без изменений) | `17e8eb77e898099c` | `17e8eb77e898099c` | `17e8eb77e898099c` |
| `sla_smoke.py` | O + правки сборки (P идентичен O) | `5d73b73c34b1f72f` | `cdd96c37723139a1` | `cdd96c37723139a1` |
| `test_sla_smoke.py` | O + правки сборки (P идентичен O) | `ded2aadfe1363f3f` | `5987ffb4afddded5` | `5987ffb4afddded5` |
| `web/guard_addon.py` | O (без изменений) | `22989a29bdb2b648` | `22989a29bdb2b648` | `22989a29bdb2b648` |
| `web/integration_web.py` | O (без изменений) | `79b32102cdb0794e` | `79b32102cdb0794e` | `79b32102cdb0794e` |
| `web/policy.py` | O + правки сборки (P идентичен O) | `2a09ac0e4e40a81a` | `dda68683fc5d98f8` | `dda68683fc5d98f8` |
| `web/requirements.txt` | O + правки сборки (P идентичен O) | `76d25e51c55d52f1` | `bbd8fcd6a77b0c3e` | `bbd8fcd6a77b0c3e` |
| `web/run_guard.py` | O (без изменений) | `0cb42e0290bd8ac7` | `0cb42e0290bd8ac7` | `0cb42e0290bd8ac7` |
| `web/test_policy.py` | O + правки сборки (P идентичен O) | `604843ffa580ecad` | `4bfe071010ff3e0d` | `4bfe071010ff3e0d` |

## Правило выбора

Для всех расходящихся файлов взята копия O: это надмножество P (глубокая AgroPlant-версия с водяным трактом, FC22 RMW и чтениями вне write-lock; LoginGuard и 18 тестов OffLocker). Копия P не содержала уникального содержимого. Выбор сделан по содержимому и результатам повторной проверки, а не по дате или числу правил.
