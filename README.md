[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

# Sporelink Connector (Java)

Экономическая нода, которая хранит балансы игроков и обрабатывает транзакции.

## Особенности
* Локальный Ledger (SQLite).
* Двухфазный коммит (2PC) для переводов между нодами.
* Ed25519 подписи запросов + защита от replay-атак.
* Фоновый recovery зависших транзакций.

## Запуск
```bash
mvn clean package
java -jar target/connector-1.0-SNAPSHOT.jar <port> <data-dir> <node-id> <hub-url>