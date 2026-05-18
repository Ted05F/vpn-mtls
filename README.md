# Защищённая VPN-система на Go с mTLS

> **Тема курсовой работы:** Разработка и исследование защищённой VPN-системы на языке Go  
> с использованием взаимной TLS-аутентификации (mTLS) в среде Ubuntu Linux

---

## Архитектура системы

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Клиентская машина                               │
│   ┌──────────────┐    TUN0 (10.8.0.x)                                  │
│   │  VPN Client  │◄──────────────────────────────────────────────────► │
│   │  (Go binary) │  mTLS 1.3 (клиентский сертификат от Vault PKI)      │
│   └──────────────┘                                                      │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │ TCP :8443  (mTLS)
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Серверная инфраструктура (Docker)                     │
│                                                                         │
│   ┌────────────┐     ┌─────────────────────────────────────────────┐   │
│   │   Caddy    │────►│           VPN Server (Go)                   │   │
│   │ (Reverse   │     │  • TLS 1.3 listener (port 8443)             │   │
│   │  Proxy)    │     │  • mTLS: RequireAndVerifyClientCert         │   │
│   │ :443/:80   │     │  • TUN interface (tun-vpn, 10.8.0.1/24)     │   │
│   └────────────┘     │  • IP pool management                       │   │
│         │            │  • Packet routing & bridging                │   │
│         │            └─────────────────┬───────────────────────────┘   │
│         │                              │                                │
│         │            ┌─────────────────▼───────────────────────────┐   │
│         │            │         Redis (session store)               │   │
│         │            │  • vpn:session:<id>    (TTL 24h)            │   │
│         │            │  • vpn:refresh:<token> (TTL 7d)             │   │
│         │            │  • vpn:active_clients  (SET)                │   │
│         │            └─────────────────────────────────────────────┘   │
│         │                                                               │
│         └──────────► ┌─────────────────────────────────────────────┐   │
│                      │         HashiCorp Vault                      │   │
│                      │  • PKI engine (Root CA → Intermediate CA)   │   │
│                      │  • Roles: vpn-server, vpn-client            │   │
│                      │  • KV-v2: /secret/vpn/*                     │   │
│                      │  • Auto-issue & revoke certificates         │   │
│                      └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Стек технологий

| Компонент | Технология | Назначение |
|-----------|-----------|------------|
| VPN Server | Go 1.22 | mTLS-сервер, маршрутизация пакетов |
| VPN Client | Go 1.22 | TUN-интерфейс, reconnect-логика |
| TLS | TLS 1.3 (только) | Шифрование + взаимная аутентификация |
| TUN interface | `songgao/water` | L3 туннелирование (Linux) |
| Session store | Redis 7 | Сессии, refresh-токены |
| PKI / Secrets | HashiCorp Vault 1.16 | Выдача и отзыв сертификатов |
| Reverse proxy | Caddy 2 | Терминация TLS, маршрутизация |
| Container | Docker + Compose | Оркестрация сервисов |
| PKI bootstrap | OpenSSL 3 + bash | Root CA → Intermediate CA → Leaf |

---

## Структура проекта

```
vpn-mtls/
├── cmd/
│   ├── server/main.go          # Точка входа сервера
│   └── client/main.go          # Точка входа клиента
├── internal/
│   ├── tls_utils/tls.go        # mTLS конфигурация (TLS 1.3)
│   ├── session/store.go        # Redis-хранилище сессий и токенов
│   ├── tunnel/
│   │   ├── server.go           # TUN-интерфейс сервера, IP-пул
│   │   ├── client.go           # TUN-интерфейс клиента
│   │   └── iface_linux.go      # Настройка сетевого интерфейса (Linux)
│   └── vault_client/vault.go   # Vault API: выдача/отзыв сертификатов
├── pkg/
│   └── cert/fetch.go           # Получение PKI-бандла из Vault
├── pki/
│   ├── scripts/
│   │   └── bootstrap_pki.sh    # Скрипт создания PKI-иерархии
│   └── configs/
│       ├── root_ca.cnf         # OpenSSL: Root CA
│       ├── intermediate_ca.cnf # OpenSSL: Intermediate CA
│       ├── server_cert.cnf     # OpenSSL: серверный сертификат
│       └── client_cert.cnf     # OpenSSL: клиентский сертификат
├── docker/
│   ├── server/Dockerfile       # Образ VPN-сервера
│   ├── client/Dockerfile       # Образ VPN-клиента
│   ├── vault/config.hcl        # Конфигурация Vault
│   └── vault-init/
│       ├── Dockerfile          # Init-контейнер
│       └── init.sh             # Скрипт инициализации Vault PKI
├── caddy/
│   └── Caddyfile               # Конфигурация reverse proxy
├── benchmark/
│   └── security_test.go        # Тесты безопасности + бенчмарки
├── docker-compose.yml
├── go.mod
├── Makefile
└── .env.example
```

---

## Быстрый старт

### Требования

- Ubuntu 22.04 / 24.04 LTS
- Docker Engine 24+ и Docker Compose v2
- Go 1.22+ (для локальной сборки)
- OpenSSL 3.x

```bash
# Проверить версии
docker --version && docker compose version
go version
openssl version
```

### 1. Клонировать репозиторий

```bash
git clone https://github.com/yourorg/vpn-mtls.git
cd vpn-mtls
cp .env.example .env
# Отредактировать .env — изменить пароли и токены
nano .env
```

### 2. Запустить весь стек

```bash
make up
```

Порядок запуска (автоматически):
1. **Redis** — ожидание `ping`
2. **Vault** — ожидание `vault status`
3. **vault_init** — создаёт PKI engine, роли, выпускает сертификаты
4. **vpn_server** — запускается после vault_init
5. **Caddy** — запускается после vpn_server
6. **vpn_client** — подключается к серверу

```bash
# Следить за логами
make logs

# Проверить статус
docker compose ps
```

### 3. Проверить TLS-соединение

```bash
make verify-tls
```

Ожидаемый вывод:
```
Connecting to localhost:8443
TLSv1.3, cipher: TLS_AES_256_GCM_SHA384
Server certificate: CN=vpn-server.internal
Client certificate: CN=demo-client.vpn.internal
Verification: OK
```

---

## PKI — управление сертификатами

### Создание PKI с нуля (без Vault)

```bash
make pki
```

Создаёт полную иерархию:
```
Root CA (10 лет)
  └── Intermediate CA (5 лет)
        ├── vpn-server.cert.pem  (1 год, serverAuth)
        └── demo-client.cert.pem (1 год, clientAuth)
```

### Выпуск нового клиентского сертификата

```bash
make pki-client
# Введите имя: alice
# → pki/output/certs/alice.cert.pem
# → pki/output/certs/alice.key.pem
```

### Отзыв сертификата

```bash
make pki-revoke
# Введите путь: pki/output/certs/alice.cert.pem
# → Сертификат отозван, CRL обновлён
```

### Через Vault (автоматически)

```bash
# Выпустить клиентский сертификат через Vault PKI
docker compose exec vault \
  vault write pki/issue/vpn-client \
    common_name="new-client.vpn.internal" \
    ttl=8760h

# Отозвать по серийному номеру
docker compose exec vault \
  vault write pki/revoke \
    serial_number="XX:XX:XX:..."
```

---

## Тестирование

### Запуск всех тестов

```bash
make test
```

### Тесты безопасности

```bash
make test-security
```

Проверяется:
- Отказ при отсутствии клиентского сертификата
- Отказ при просроченном сертификате
- Отказ при сертификате от чужого CA
- Отказ TLS версий < 1.3
- Набор шифров (только TLS 1.3)
- Отключение session tickets
- Отсутствие лишних открытых портов

### Бенчмарки

```bash
make bench
```

| Тест | Метрика |
|------|---------|
| `BenchmarkTLSHandshake` | Время одного mTLS handshake |
| `BenchmarkConcurrentConnections` | Параллельные соединения (10 горутин) |
| `BenchmarkThroughput` | Пропускная способность туннеля (MB/s) |

---

## Переменные окружения

| Переменная | Сервер | Клиент | Описание |
|-----------|:------:|:------:|----------|
| `LISTEN_ADDR` | ✓ | — | Адрес прослушивания (`0.0.0.0:8443`) |
| `REDIS_ADDR` | ✓ | — | Redis адрес (`redis:6379`) |
| `REDIS_PASSWORD` | ✓ | — | Redis пароль |
| `VAULT_ADDR` | ✓ | ✓ | Vault HTTP адрес |
| `VAULT_TOKEN` | ✓ | ✓ | Vault токен |
| `TUN_SUBNET` | ✓ | — | Подсеть туннеля (`10.8.0.0/24`) |
| `TUN_GW` | ✓ | — | Шлюз туннеля (`10.8.0.1`) |
| `SERVER_ADDR` | — | ✓ | Адрес сервера для подключения |
| `CLIENT_NAME` | — | ✓ | Имя клиента (CN сертификата) |
| `LOG_LEVEL` | ✓ | ✓ | Уровень логирования (`debug/info/warn`) |

---

## Описание ключевых компонентов

### mTLS конфигурация (`internal/tls_utils/tls.go`)

- Только TLS 1.3 (`MinVersion = MaxVersion = VersionTLS13`)
- `ClientAuth: tls.RequireAndVerifyClientCert` — клиент обязан предъявить сертификат
- Дополнительная проверка `extendedKeyUsage` (clientAuth / serverAuth)
- `SessionTicketsDisabled: true` — предотвращает возобновление сессии

### Сессии в Redis (`internal/session/store.go`)

- Ключ `vpn:session:<uuid>` с TTL 24 часа
- Refresh-токены `vpn:refresh:<uuid>` с отметкой об отзыве
- SET `vpn:active_clients` для быстрого подсчёта активных клиентов
- Атомарные pipeline-операции для консистентности

### TUN-интерфейс (`internal/tunnel/`)

- Устройство `/dev/net/tun` через библиотеку `songgao/water`
- Простое frame-мультиплексирование: 4-байтовый префикс длины поверх TLS
- IP-пул с автоматической выдачей и освобождением адресов
- Маршрутизация пакетов: фильтрация по destination IP (поле 16–20 IPv4)

### Vault PKI (`internal/vault_client/vault.go`)

- Endpoint `pki/issue/<role>` для выдачи сертификатов
- Endpoint `pki/revoke` для немедленного отзыва
- KV-v2 (`secret/vpn/*`) для хранения конфигурации
- Политики: `vpn-server` (может выдавать клиентские серты), `vpn-client` (только получение)

---

## Безопасность: принятые меры

| Угроза | Контрмера |
|--------|-----------|
| Перехват трафика | TLS 1.3 с AEAD-шифрами (AES-256-GCM, ChaCha20) |
| Подделка клиента | mTLS — обязательный клиентский сертификат |
| Кража сертификата | Отзыв через Vault, CRL |
| Повтор сессии | Session tickets отключены |
| Слабые шифры | Только TLS 1.3 (нет RC4, 3DES, CBC) |
| Компрометация CA | Двухуровневая PKI (Root CA offline) |
| Утечка секретов | Vault — ни один ключ не хранится на диске вне Vault |
| Брутфорс | Mutual auth — без сертификата соединение невозможно |

---

## Структура курсовой работы

```
Курсовая работа
├── Введение
│   ├── Актуальность защиты сетевых соединений
│   ├── Цель и задачи исследования
│   └── Обзор существующих VPN-решений (OpenVPN, WireGuard)
│
├── Глава 1. Теоретические основы
│   ├── 1.1 Протокол TLS 1.3: handshake, AEAD, forward secrecy
│   ├── 1.2 Взаимная аутентификация (mTLS): отличие от односторонней
│   ├── 1.3 PKI: CA, цепочки доверия, CRL, OCSP
│   ├── 1.4 TUN/TAP устройства в Linux
│   └── 1.5 Redis как хранилище состояния
│
├── Глава 2. Проектирование системы
│   ├── 2.1 Архитектура (диаграмма компонентов)
│   ├── 2.2 PKI-иерархия: Root CA → Intermediate CA → листовые сертификаты
│   ├── 2.3 Жизненный цикл сессии (Connect → Auth → Tunnel → Disconnect)
│   ├── 2.4 Схема взаимодействия с Vault
│   └── 2.5 Схема обработки пакетов в TUN-туннеле
│
├── Глава 3. Реализация
│   ├── 3.1 VPN-сервер: mTLS listener, IP-пул, сессии
│   ├── 3.2 VPN-клиент: TUN-интерфейс, reconnect с exponential backoff
│   ├── 3.3 PKI-инфраструктура: bash-скрипты и OpenSSL-конфиги
│   ├── 3.4 Интеграция Vault: выдача и отзыв сертификатов
│   ├── 3.5 Redis: структура данных сессий и refresh-токенов
│   └── 3.6 Caddy: reverse proxy с mTLS enforcement
│
├── Глава 4. Тестирование и оценка
│   ├── 4.1 Тесты безопасности: 6 сценариев атак
│   ├── 4.2 Нагрузочное тестирование: latency, throughput, concurrent clients
│   ├── 4.3 Анализ результатов бенчмарков
│   └── 4.4 Сравнение с OpenVPN и WireGuard
│
├── Заключение
│   ├── Достигнутые результаты
│   ├── Ограничения прототипа
│   └── Направления дальнейшего развития

```

---

## Полезные команды

```bash
# Статус всех контейнеров
docker compose ps

# Подключиться к Vault UI
make vault-ui
# → http://localhost:8200 (токен из .env)

# Проверить активные сессии в Redis
docker compose exec redis \
  redis-cli -a "$REDIS_PASSWORD" SMEMBERS vpn:active_clients

# Посмотреть сертификаты Vault
docker compose exec vault \
  vault list pki/certs

# Ручной тест mTLS (без клиентского сертификата — должен упасть)
openssl s_client -connect localhost:8443 -tls1_3 2>&1 | grep "alert"

# Полный mTLS тест (с клиентским сертификатом — должен пройти)
openssl s_client \
  -connect localhost:8443 \
  -cert pki/output/certs/demo-client.cert.pem \
  -key  pki/output/certs/demo-client.key.pem \
  -CAfile pki/output/intermediate/certs/ca-chain.cert.pem \
  -tls1_3

# Проверить версию TLS сервера
nmap --script ssl-enum-ciphers -p 8443 localhost
```

---

## Лицензия

MIT — учебный проект. Не использовать в production без дополнительного аудита безопасности.
