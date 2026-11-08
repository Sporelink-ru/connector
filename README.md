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