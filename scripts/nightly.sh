#!/usr/bin/env bash
# Ночной прогон RSM: выгрузки из всех источников → модель → отчёты → NetBox.
# Падение одного источника не останавливает прогон (данные источника останутся от прошлого раза,
# а его liveness-сигналы «протухнут» через lifecycle.freshness_hours).
#
# Переменные (обычно в /etc/rsm/env, см. deploy/systemd/rsm.service):
#   RSM_SUBNETS="10.0.0.0/16 10.1.0.0/16"   подсети для nmap
#   RSM_INVENTORY=/opt/ansible/inventories/prod
#   RSM_KUBECONFIG=/etc/rsm/kubeconfig        склеенный kubeconfig с rsm-reader всех кластеров
#   RSM_VCENTERS="vc01.corp.example.com"
#   RSM_DNS_ZONES="corp.example.com"  RSM_DNS_SERVER=ns1.corp.example.com
#   ZABBIX_URL, ZABBIX_TOKEN, NETBOX_URL, NETBOX_TOKEN
set -uo pipefail
cd "$(dirname "$0")/.."
PY="${PY:-.venv/bin/python}"
log() { echo "[$(date -u +%FT%TZ)] $*"; }
step() { local name="$1"; shift; log "$name"; "$@" || log "  ⚠ $name: ошибка, продолжаю"; }

[ -n "${ZABBIX_URL:-}" ]     && step "zabbix"  "$PY" -m rsm fetch zabbix
[ -n "${RSM_KUBECONFIG:-}" ] && step "k8s"     "$PY" -m rsm fetch k8s --kubeconfig "$RSM_KUBECONFIG"
[ -n "${RSM_SUBNETS:-}" ]    && step "nmap"    "$PY" -m rsm fetch nmap $RSM_SUBNETS
[ -n "${RSM_INVENTORY:-}" ]  && step "ansible" "$PY" -m rsm fetch ansible -i "$RSM_INVENTORY"
for vc in ${RSM_VCENTERS:-}; do
  step "vcenter $vc" pwsh -NoProfile -File deploy/vcenter/export_vcenter.ps1 -Server "$vc" -Out "data/raw/vcenter/$vc.json"
done
for zone in ${RSM_DNS_ZONES:-}; do
  step "dns $zone" scripts/export_dns.sh "$zone" "${RSM_DNS_SERVER:?RSM_DNS_SERVER}"
done

# Подтверждения из NetBox → модель → обратно в NetBox.
[ -n "${NETBOX_URL:-}" ] && step "netbox pull" "$PY" -m rsm netbox pull
"$PY" -m rsm run || { log "rsm run упал"; exit 1; }
[ -n "${NETBOX_URL:-}" ] && step "netbox sync" "$PY" -m rsm netbox sync --apply
log "готово: data/reports/index.html"
