# Запуск vpn-mtls с нуля (Linux)

Инструкция для локального стенда: **Vault** (PKI), **Redis**, **vpn-server**, **vpn-client**. Сервер и клиент создают интерфейсы **TUN** — для этого обычно нужны права **root** или capability `CAP_NET_ADMIN`.

---

## 1. Что установить

| Компонент | Назначение |
|-----------|------------|
| **Go** 1.22+ | Сборка (`go build`). Если в системе нет `go`, можно использовать toolchain из каталога проекта (см. ниже). |
| **Vault** | Выдача сертификатов mTLS из PKI (`vault` CLI или Docker). |
| **Redis** | Хранилище сессий на сервере (`127.0.0.1:6379` по умолчанию). |

Пример установки Redis на Ubuntu:

```bash
sudo apt install -y redis-server
sudo systemctl start redis-server
redis-cli -h 127.0.0.1 ping   # ожидается PONG
```

---

## 2. Клонирование и сборка

```bash
cd ~/Desktop/vpn-mtls   # или ваш путь к репозиторию
```

Подтянуть зависимости и собрать бинарники:

```bash
export PATH="$HOME/Desktop/vpn-mtls/.tools/go/bin:$PATH"   # если системного go нет
go mod tidy
go build -o vpn-server ./cmd/server
go build -o vpn-client ./cmd/client
```

Если команда `go` не найдена и каталога `.tools/go` нет — установите Go с [go.dev/dl](https://go.dev/dl/) или `sudo snap install go`, затем снова выполните `go mod tidy` и `go build`.

---

## 3. Vault в режиме разработки

В **отдельном терминале** запустите Vault (не закрывайте окно):

```bash
vault server -dev -dev-listen-address="0.0.0.0:8200"
```

Скопируйте **Root Token** из вывода. В другом терминале:

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<Root Token из предыдущего шага>
vault status   # Sealed: false
```

После **каждого** перезапуска `vault server -dev` данные в памяти обнуляются — PKI и токен нужно настроить заново.

---

## 4. Один раз: включить PKI и роли под этот проект

Код обращается к путям `pki/issue/vpn-server`, `pki/issue/vpn-client`, `pki/cert/ca`. Корневой CA должен жить **дольше**, чем запрашиваемые сертификаты (иначе Vault вернёт 400). Ниже CA на **87600h** (~10 лет), роли совместимы с CN из кода.

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<ваш токен>

vault secrets enable -path=pki pki

vault write -field=certificate pki/root/generate/internal \
  common_name="vpn-mtls Lab Root" \
  ttl=87600h

vault write pki/config/urls \
  issuing_certificates="http://127.0.0.1:8200/v1/pki/ca" \
  crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl"

vault write pki/roles/vpn-server \
  allowed_domains="internal" \
  allow_subdomains=true \
  max_ttl=8760h \
  key_type=rsa key_bits=2048

vault write pki/roles/vpn-client \
  allowed_domains="vpn.internal" \
  allow_subdomains=true \
  max_ttl=8760h \
  key_type=rsa key_bits=2048 \
  client_flag=true
```

Проверка выпуска:

```bash
vault write -field=certificate pki/issue/vpn-client \
  common_name="vpn-client.vpn.internal" ttl=1h >/dev/null && echo OK
```

Опционально: срок жизни выписываемых сертификатов задаётся переменной **`VPN_CERT_TTL`** (формат как у Vault, например `720h`). В коде TTL дополнительно **ограничивается датой окончания CA**, чтобы не было ошибки при коротком lab-CA.

---

## 5. Переменные окружения

Общие для сервера и клиента:

| Переменная | Обязательно | По умолчанию | Описание |
|------------|---------------|----------------|----------|
| `VAULT_ADDR` | нет | `http://127.0.0.1:8200` | HTTP(S) адрес Vault |
| `VAULT_TOKEN` | **да** | — | Токен с правами на PKI |
| `LOG_LEVEL` | нет | `info` | Уровень логов |

Сервер дополнительно:

| Переменная | По умолчанию |
|------------|----------------|
| `REDIS_ADDR` | `127.0.0.1:6379` |
| `REDIS_PASSWORD` | пусто |
| `LISTEN_ADDR` | `0.0.0.0:8443` |
| `TUN_SUBNET` | `10.8.0.0/24` |
| `TUN_GW` | `10.8.0.1` |

Клиент дополнительно:

| Переменная | По умолчанию |
|------------|----------------|
| `SERVER_ADDR` | `127.0.0.1:8443` |
| `CLIENT_NAME` | `vpn-client` (входит в CN сертификата как `{CLIENT_NAME}.vpn.internal`) |

---

## 6. Запуск сервера

Нужны: работающие Vault и Redis. Создание **TUN** требует повышенных прав.

```bash
cd ~/Desktop/vpn-mtls
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<ваш токен>

sudo -E ./vpn-server
```

В логах ожидаются строки вроде `TUN server interface ready`, `VPN server listening`, `health server started`. HTTP-проверка здоровья слушает порт **8080** (`curl -s localhost:8080` может вернуть `OK`).

Остановка: **Ctrl+C**.

---

## 7. Запуск клиента

В **другом терминале** (сервер должен быть запущен). Переменные нужно задать в **этой же** сессии shell либо передать явно в `sudo`:

```bash
cd ~/Desktop/vpn-mtls
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<тот же токен>
export SERVER_ADDR=127.0.0.1:8443

sudo -E ./vpn-client
```

Если `sudo -E` не передаёт переменные (зависит от настроек `sudoers`), используйте:

```bash
sudo --preserve-env=VAULT_ADDR,VAULT_TOKEN,SERVER_ADDR ./vpn-client
```

или одну строку без предварительного `export`:

```bash
sudo VAULT_ADDR=http://127.0.0.1:8200 \
     VAULT_TOKEN=<ваш токен> \
     SERVER_ADDR=127.0.0.1:8443 \
     ./vpn-client
```

После подключения в логах клиента должны появиться сообщения об установленной TLS-сессии и настройке TUN (`TUN configured from server`).

---

## 8. Типичные ошибки

| Сообщение | Что сделать |
|-----------|-------------|
| `connection refused` к `:8200` | Запустить Vault, проверить `VAULT_ADDR`. |
| `VAULT_TOKEN is not set` | Экспортировать токен в том же терминале или передать переменные в `sudo` (см. выше). |
| `redis ping failed` | Запустить Redis, проверить `redis-cli ping`. |
| `create TUN interface: operation not permitted` | Запускать `./vpn-server` и `./vpn-client` через `sudo` или выдать бинарнику `cap_net_admin` (`setcap`). |
| `connection refused` к `:8443` | Убедиться, что сервер запущен и слушает порт; клиент подключается к `SERVER_ADDR` того же хоста/сети. |
| Ошибка Vault про TTL и CA | Пересоздать корень PKI с большим `ttl` (раздел 4) или задать меньший `VPN_CERT_TTL`; в коде TTL также режется по дате окончания CA. |

---

## 9. Порты по умолчанию

- **8200** — Vault  
- **6379** — Redis  
- **8443** — VPN (mTLS)  
- **8080** — простой HTTP «health» на сервере  

На межсетевом экране при необходимости откройте только то, что нужно для вашей схемы (часто 8443 между клиентом и сервером).

---

## 10. Краткий чеклист «с нуля»

1. Redis запущен, `redis-cli ping` → `PONG`.  
2. Vault запущен, `vault status` без ошибки соединения.  
3. Выполнена настройка PKI из раздела 4 (один раз после старта dev Vault).  
4. `go build` для `vpn-server` и `vpn-client`.  
5. `sudo -E ./vpn-server` с `VAULT_TOKEN`.  
6. `sudo -E ./vpn-client` с тем же `VAULT_TOKEN` и `SERVER_ADDR` на ваш сервер.
