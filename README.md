# RSM — прототип ресурсно-сервисной модели

Автоматически отвечает на вопрос **«какой сервер чей»** для парка из сотен серверов (legacy + Kubernetes):
собирает данные из discovery-источников, склеивает их в конфигурационные единицы (CI), определяет
владельца по правилам с объяснимыми уликами, ведёт историю и жизненный цикл, ставит задачи командам
и публикует результат в NetBox.

```
 Источники (fetch)            Разбор (collect)   Модель (build)                       CMDB (reconcile)          Выход (report / netbox)
 nmap · DNS · vCenter    ─┐                      • склейка CI по UUID/serial/MAC/имени  • история изменений      • HTML-отчёт + CSV-реестры
 Ansible · Zabbix        ─┼─► data/raw ─► staging • правила атрибуции → улики → статус  • active/stale/на вывод  • задачи командам (tasks.jsonl)
 Kubernetes · Git (каталог)┘                      • сервисный слой: сервис↔ns↔ноды       • подтверждения людей    • NetBox: tenant + rsm_* поля
```

Ключевые принципы (из исходного плана):
- сервер принадлежит **команде и сервису**, а не человеку (человек из «Notes» переводится в команду через `people.yaml`);
- владельцы назначаются **правилами**, а не вручную; каждое решение объяснимо (`rsm show <host>`);
- уверенность складывается из улик: `auto` → можно доверять, `needs-confirmation` → команда подтверждает одной командой, `unowned` → триаж;
- ноды Kubernetes принадлежат платформе, а нагрузки на них — командам (доля CPU requests, наследование критичности);
- ничего не удаляется автоматически: пропавшие хосты становятся `stale` → `decommission-candidate` → задача владельцу.

---

## Структура

| Путь | Что это |
|---|---|
| `rsm/collectors/` | разбор выгрузок: `nmap`, `dns`, `ansible`, `vcenter`, `zabbix`, `k8s`, `git`, `manual` |
| `rsm/merge.py` | склейка наблюдений в CI (UUID с учётом перестановки байт, serial, MAC, имя; IP — только как слабый ключ) |
| `rsm/attribution.py` | движок правил, noisy-OR по уликам, статусы, конфликты |
| `rsm/servicemodel.py` | сервисы ↔ namespaces ↔ workloads ↔ ноды; showback по командам |
| `rsm/cmdb.py` | локальная CMDB (SQLite): история, lifecycle, подтверждения, задачи |
| `rsm/netbox.py` | bootstrap/sync/pull для NetBox (dry-run по умолчанию) |
| `rsm/policy.py` | policy-as-code для CI: labels в манифестах, tags в Terraform |
| `rsm/fetch.py` | выгрузки из живых систем: `kubectl`, Zabbix API, `nmap`, Ansible |
| `config/` | **всё, что вы настраиваете**: словари, каталог сервисов, правила, люди, ручные подтверждения |
| `deploy/` | RBAC для K8s, Kyverno-политика, Ansible-плейбуки, PowerCLI-выгрузка vCenter, systemd, GitLab CI |
| `scripts/` | `nightly.sh` (весь прогон), `export_dns.sh` (AXFR → CSV), `local_netbox.sh` (тестовый NetBox в Docker) |
| `demo-data/` | появится после `make demo` |

Зависимости: Python ≥ 3.10 и PyYAML. Внешние инструменты нужны только для соответствующих источников.

---

## Шаг 0. Попробовать на демо (10 минут, на ноутбуке)

Демо-генератор создаёт вымышленную компанию на ~290 серверов с реалистичным «мусором» в данных
и прогоняет три дня discovery (15.09 → 08.10 → 22.10), чтобы были видны stale-хосты и история.

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

```bash
make demo
```

```bash
make demo-open
```

Ожидаемый итог: ~76% серверов с владельцем `auto`/`confirmed`, ~17% «нужно подтвердить» (и у всех
кандидат верный), ни одной ошибочной автоматической атрибуции, 4 stale и 9 кандидатов на вывод, 88 задач.

Что посмотреть в демо — каждый пункт соответствует реальной проблеме legacy-инвентаризации:

| Команда | Что демонстрирует |
|---|---|
| `.venv/bin/python -m rsm --data-dir demo-data show prod-billing-app-05` | **конфликт**: тег vCenter `owner=crm` против Zabbix, Ansible и каталога (`billing`) → задача на разбор |
| `... show lab-02` | склейка vCenter + Ansible по **UUID с переставленными байтами**, хотя ОС называет себя `localhost` |
| `... show paygw01` | алиасы: `Payments` / `pay` / `платежи` → команда `payments`; сервис из каталога по имени хоста |
| `... show crm-app-01` | legacy без Ansible: владелец из **Notes ВМ** («owner: s.kuznetsov» → `people.yaml` → `crm`) + каталог |
| `... show k8s-prod-w-07` | нода K8s: владелец `platform`, но видно, чьи нагрузки на ней, критичность **унаследована** от нагрузок |
| `... show web-old-07` | **зомби**: жив только в Zabbix и DNS, его IP уже занят `prod-web-portal-08` (ip-conflict) |
| `... query --status unowned` | ничейные: shadow IT (только nmap), забытые лабы |
| `... query --lifecycle decommission-candidate` | не подают признаков жизни > 30 дней |
| `... tasks --assignee platform` | очередь триажа |
| `... netbox sync` | план записи в NetBox без NetBox (офлайн dry-run) → `demo-data/reports/netbox-plan.json` |

Подтверждение владельца (так команды закрывают задачи `confirm-owner`):

```bash
.venv/bin/python -m rsm --data-dir demo-data confirm old-jira --team web --service legacy-devtools --by k.volkov
```

```bash
.venv/bin/python -m rsm --data-dir demo-data run --skip-collect
```

---

## Шаг 1. Развернуть на рабочем хосте (неделя 1)

Нужна Linux-ВМ в management-сети с доступом к vCenter, Zabbix, API кластеров K8s, SSH до серверов
(через существующий Ansible) и разрешением сканировать подсети.

1. Установить инструменты: `python3` ≥ 3.10, `kubectl`, `nmap`, `ansible-core`, `dnsutils` (`dig`),
   для vCenter — `pwsh` + `Install-Module VMware.PowerCLI`.
2. Завести **read-only** доступы (все — сервисные учётки, не личные):

   | Система | Доступ |
   |---|---|
   | vCenter | роль Read-only на корне, учётка `svc-rsm` |
   | Zabbix | API-токен пользователя с правом чтения нужных host groups |
   | Ansible | существующий SSH-ключ/инвентори (плейбук только читает факты) |
   | Kubernetes | ServiceAccount `rsm-reader` (шаг 4) — без доступа к Secret |
   | DNS | `allow-transfer` для IP хоста RSM (или выгрузка из AD DNS) |
   | NetBox | API-токен с правом записи на dcim/virtualization/tenancy/extras (шаг 5) |
   | Сеть | согласовать с ИБ окно и подсети для `nmap` (без root, `-sT`) |

3. Разложить репозиторий:

```bash
sudo useradd -r -m -d /opt/rsm rsm && sudo -u rsm git clone <repo-url> /opt/rsm
```

```bash
cd /opt/rsm && sudo -u rsm python3 -m venv .venv && sudo -u rsm .venv/bin/pip install -r requirements.txt
```

4. Создать `/etc/rsm/env` (права `600`, владелец `rsm`) — переменные описаны в шапке `scripts/nightly.sh`:
   `RSM_SUBNETS`, `RSM_INVENTORY`, `RSM_KUBECONFIG`, `RSM_VCENTERS`, `RSM_DNS_ZONES`, `RSM_DNS_SERVER`,
   `ZABBIX_URL`, `ZABBIX_TOKEN`, `NETBOX_URL`, `NETBOX_TOKEN`.

---

## Шаг 2. Первичный inventory (недели 1–2)

Каждый источник сначала выгружается в `data/raw/`, затем разбирается. Источники независимы — подключайте
их по одному и после каждого смотрите отчёт. Всё ниже выполняется из `/opt/rsm` от пользователя `rsm`
(в примерах `rsm` = `.venv/bin/python -m rsm`).

**2.1. DNS** — связка имя ↔ IP, «хвосты» от выведенных серверов.

```bash
scripts/export_dns.sh corp.example.com ns1.corp.example.com
```

**2.2. Сетевой скан** — всё, что отвечает в сети, включая то, о чём никто не знает.

```bash
.venv/bin/python -m rsm fetch nmap 10.10.0.0/16 10.20.0.0/16
```

**2.3. vCenter** — UUID, MAC, теги, Custom Attributes, Notes, power state.

```bash
pwsh deploy/vcenter/export_vcenter.ps1 -Server vc01.corp.example.com
```

**2.4. Zabbix** — группы, теги, доступность агента (зомби в мониторинге видны как недоступные).

```bash
.venv/bin/python -m rsm fetch zabbix
```

**2.5. Ansible** — факты ОС, product UUID/serial, сервисы, группы и hostvars инвентори.

```bash
.venv/bin/python -m rsm fetch ansible -i /opt/ansible/inventories/prod
```

**2.6. Git** — каталог сервисов из `catalog-info.yaml` (Backstage) и `CODEOWNERS`. Положите эти файлы
в `data/raw/git/<repo>/` (sparse checkout или выгрузка через API GitLab).

**2.7. Первый прогон:**

```bash
.venv/bin/python -m rsm run
```

Откройте `data/reports/index.html`, блок «Источники discovery»: сколько хостов видит каждый источник,
сколько видны только одному, сколько только nmap (shadow IT).

> ⚠️ Проверьте `ip_ignore` в `config/rsm.yaml`: там CIDR подов/сервисов Kubernetes и docker-bridge.
> Если они пересекаются с корпоративными подсетями, IP реальных серверов перестанут участвовать в склейке
> (в демо так и случилось на первом прогоне: дефолтный service CIDR `10.96.0.0/12` накрыл `10.100.x.x`).

---

## Шаг 3. Словари, каталог и правила (недели 2–3, итерациями)

Это основная работа. Цикл короткий: правите `config/` → перестраиваете модель **без повторного discovery**:

```bash
.venv/bin/python -m rsm run --skip-collect
```

| Файл | Что заполнить | Откуда взять |
|---|---|---|
| `config/dictionary.yaml` | команды и все их написания (алиасы), окружения, критичность, on-call | оргструктура, Slack-каналы дежурств |
| `config/people.yaml` | логин → команда | LDAP/AD: `ldapsearch ... sAMAccountName department` |
| `config/service_catalog.yaml` | 20–30 главных сервисов: владелец, критичность, `hosts`-регэкспы, `k8s_namespaces` | Backstage/вики/CMDB, опрос тимлидов |
| `config/attribution_rules.yaml` | ваши категории тегов vCenter, группы Zabbix, конвенции имён, подсети команд | смотрите на реальные значения в `data/staging/*.jsonl` |
| `config/ownership_overrides.csv` | то, что известно точно, но не выводится (legacy-хвосты) | ответы команд |

Как читать результат:
- `rsm show <host>` — все улики с весами и альтернативы: почему выбрана эта команда;
- раздел отчёта «Пополнить словари» — значения, которые встречаются в источниках, но неизвестны словарю
  (например `ml-team`, `recsys`) — их вес занижен вдвое, пока вы их не добавите;
- `data/reports/coverage.json` — метрики для сравнения итераций.

Как подбирать веса: явные метки владения 0.85–0.95, группы мониторинга/инвентаря ~0.7, конвенции имён 0.5–0.6,
подсети 0.4–0.5, человек из описания 0.6. Пороги — в `config/rsm.yaml → thresholds`.
Контроль качества: раз в итерацию берите 20 случайных `auto`-хостов и проверяйте с командами.
Цель — ≥ 80% `auto + confirmed` без ошибок в выборке.

---

## Шаг 4. Kubernetes (параллельно с шагом 3)

1. В каждом кластере создать read-only ServiceAccount и kubeconfig:

```bash
deploy/k8s/make-kubeconfig.sh admin@k8s-prod-eu k8s-prod-eu
```

2. Склеить kubeconfig'и всех кластеров в один файл для RSM:

```bash
KUBECONFIG=kubeconfig-rsm-k8s-prod-eu:kubeconfig-rsm-k8s-stage kubectl config view --flatten > /etc/rsm/kubeconfig
```

3. Выгрузить все кластеры (ноды, namespaces, workloads, поды):

```bash
.venv/bin/python -m rsm fetch k8s --kubeconfig /etc/rsm/kubeconfig
```

4. Поправить в `attribution_rules.yaml` правило `k8s-cluster-environment` под ваши имена кластеров.
5. Разметить namespaces через GitOps (а не руками в кластере): `team`, `service`, `env`.
   Список того, что разметить, — раздел отчёта «Kubernetes namespaces» и задачи `label-namespace`.
6. Включить Kyverno-политику в режиме Audit, через 2–4 недели — Enforce:

```bash
kubectl apply -f deploy/k8s/kyverno-require-ownership-labels.yaml
```

---

## Шаг 5. NetBox как source of truth (недели 3–4)

Если NetBox ещё нет — официальный docker-вариант:

```bash
git clone -b release https://github.com/netbox-community/netbox-docker.git && cd netbox-docker
```

```bash
docker compose pull && docker compose up -d
```

```bash
docker compose exec netbox /opt/netbox/netbox/manage.py createsuperuser
```

Затем в UI создайте API-токен для RSM и пропишите `NETBOX_URL` / `NETBOX_TOKEN` в `/etc/rsm/env`.
Поддерживаются оба формата токенов: v2 из NetBox ≥ 4.5 (`nbt_<key>.<token>`, RSM сам шлёт `Bearer`) и старый v1 (`Token`).

Чтобы сначала попробовать всё на локальном NetBox с демо-данными (так прототип и проверялся, NetBox 4.7.3):

```bash
scripts/local_netbox.sh up
```

```bash
source local/netbox.env && make demo
```

```bash
.venv/bin/python -m rsm --data-dir demo-data netbox bootstrap --apply && .venv/bin/python -m rsm --data-dir demo-data netbox sync --apply
```

Остановить — `scripts/local_netbox.sh down`, удалить вместе с данными — `scripts/local_netbox.sh destroy`.

Публикация (по умолчанию всегда dry-run; план — в `data/reports/netbox-plan.json`):

```bash
.venv/bin/python -m rsm netbox bootstrap
```

```bash
.venv/bin/python -m rsm netbox bootstrap --apply
```

```bash
.venv/bin/python -m rsm netbox sync
```

```bash
.venv/bin/python -m rsm netbox sync --apply
```

Модель в NetBox: команда → **Tenant** (группа `teams`); сервис, окружение, критичность, статус владения, улики,
lifecycle → custom fields `rsm_*`; кластеры K8s и vSphere → **Cluster**; ВМ → Virtual Machine, железо → Device;
теги `rsm-unowned`, `rsm-needs-confirmation`, `rsm-conflict`, `rsm-stale` для фильтров.

Подтверждение в NetBox: команда ставит Tenant (и при необходимости `rsm_service` / `rsm_environment`) и галочку
`rsm_owner_confirmed` → `rsm netbox pull` забирает подтверждения → следующий прогон считает их `confirmed`.
Порядок важен: `pull` → `run` (подтверждения читаются на стадии collect, поэтому `run --skip-collect` их не увидит) → `sync`;
так и сделано в `scripts/nightly.sh`.

Что гарантирует `sync`:
- идемпотентен: повторный прогон без изменений в модели даёт пустой план;
- у подтверждённых объектов не трогает Tenant и `rsm_service` / `rsm_environment` / `rsm_criticality` / `rsm_support_model`,
  даже если в RSM другое значение (правка человека в NetBox главнее);
- сохраняет чужие теги (всё, что не `rsm-*`), ничего не удаляет;
- если хост сменил тип (ВМ ↔ железо), объект не пересоздаёт, а выводит его в `type_mismatch` — поправьте вручную.

---

## Шаг 6. Workflow владельцев (постоянно)

Задачи генерируются на каждом прогоне, закрываются сами, когда причина устранена:

| Тип | Кому | Что сделать |
|---|---|---|
| `assign-owner` | триаж (`triage_team`) | найти владельца ничейного хоста |
| `confirm-owner` | команде-кандидату | подтвердить или отклонить |
| `resolve-conflict` | триаж | разобраться, чей хост, исправить неверную метку |
| `fill-attributes` | владельцу | дозаполнить service/env/criticality |
| `verify-decommission` | владельцу | подтвердить вывод или вернуть хост в работу |
| `label-namespace` / `register-service` | владельцу / триаж | разметить namespace / завести сервис в каталог |
| `fix-ip-conflict` / `fix-identity` | триаж | дубли IP, разные машины под одним именем |

```bash
.venv/bin/python -m rsm tasks --assignee payments
```

Задачи лежат в `data/reports/tasks.jsonl` — их удобно заводить в Jira/GitLab по одной на команду в неделю.
Способы подтвердить владельца (любой): `rsm confirm`, строка в `ownership_overrides.csv`, галочка в NetBox,
или «прибить» владельца к хосту через `deploy/ansible/rsm_owner_fact.yml` (тогда он приезжает с фактами Ansible).

Эскалация ничейных: платформа (триаж) → бизнес-владелец подсети/проекта → если за 30 дней никто не признал —
кандидат на выключение по согласованию с ИБ.

---

## Шаг 7. Policy-as-code (неделя 4+)

Чтобы новые ресурсы не появлялись без владельца:

```bash
.venv/bin/python -m rsm policy check k8s/ terraform/
```

```bash
helm template chart/ | .venv/bin/python -m rsm policy check -
```

Шаблон джоба для репозиториев приложений — в конце `deploy/ci/gitlab-ci.yml`. В кластерах то же самое
делает Kyverno (шаг 4). Пример нарушений: `make policy`.

---

## Шаг 8. Расписание и ежедневная отчётность

Вариант A — systemd на хосте RSM:

```bash
sudo cp deploy/systemd/rsm.service deploy/systemd/rsm.timer /etc/systemd/system/ && sudo systemctl daemon-reload
```

```bash
sudo systemctl enable --now rsm.timer
```

Вариант B — расписание GitLab + shell-раннер на хосте RSM (`deploy/ci/gitlab-ci.yml`, джоб `nightly`).

Отчёт `data/reports/index.html` публикуйте любым статическим хостингом во внутренней сети; метрики из
`coverage.json` (доля владельцев, ничейные, stale, NS без владельца, открытые задачи) удобно выводить
в Grafana и разбирать на еженедельной встрече платформы.

---

## Шпаргалка

| Команда | Что делает |
|---|---|
| `rsm fetch k8s\|zabbix\|nmap\|ansible ...` | выгрузить сырые данные из живой системы |
| `rsm collect [--only k8s,zabbix]` | разобрать `data/raw` → `data/staging` |
| `rsm build` / `reconcile` / `report` | стадии по отдельности |
| `rsm run [--skip-collect] [--now ISO]` | всё сразу |
| `rsm show <host\|ip\|id>` | карточка сервера с уликами |
| `rsm query --team X --status unowned --format csv` | выборки из CMDB |
| `rsm confirm <host> --team X --service Y --by login` | подтвердить владельца |
| `rsm tasks [--assignee X] [--type Y]` | очередь задач |
| `rsm netbox bootstrap\|sync\|pull [--apply]` | NetBox |
| `rsm policy check <paths\|->` | проверка меток владения в IaC |
| `make demo` / `make test` | демо и тесты |

Глобальные флаги: `--config DIR` (по умолчанию `./config`), `--data-dir DIR` (по умолчанию `./data`).

---

## Ограничения прототипа и что проверено

- **Проверено на демо-данных**: склейка, атрибуция, сервисный слой, CMDB/lifecycle/задачи, отчёты, policy;
  12 юнит-тестов (`make test`).
- **Проверено на живом NetBox 4.7.3** (локальный Docker, токен v2): `bootstrap --apply` и `sync --apply` для 289 объектов,
  идемпотентность обоих, PATCH изменений, пагинация, `pull` подтверждений → `confirmed` в модели, защита
  подтверждённых полей и чужих тегов.
- **Не проверено на живых системах** (нет доступа из среды, где писался прототип): `rsm fetch` для Zabbix/K8s/nmap/Ansible
  и PowerCLI-скрипт. Форматы взяты из штатных выгрузок (`kubectl -o json`, `nmap -oX`, Zabbix `host.get`, факты Ansible),
  но первый запуск делайте на одном источнике.
- NetBox: IP хранятся в поле `rsm_ips`, интерфейсы и IP-объекты не создаются; сервисный слой (сервисы,
  namespaces, workloads) живёт в отчёте/каталоге — для него в NetBox понадобится плагин custom objects либо Backstage/iTop.
- Облака (AWS/GCP/Azure/Yandex) не подключены: добавьте коллектор по образцу `rsm/collectors/vcenter.py`
  (функция `collect(cfg)` возвращает наблюдения формата `observation(...)`) и зарегистрируйте его в `rsm/collectors/__init__.py`.
- Локальная CMDB — SQLite на одном хосте; для нескольких сотен серверов этого достаточно.
