#!/usr/bin/env bash
# Выгрузка A-записей зоны в data/raw/dns/<zone>.csv через AXFR.
#   scripts/export_dns.sh corp.example.com ns1.corp.example.com
# AXFR должен быть разрешён для хоста RSM. Для Active Directory DNS вместо этого:
#   Get-DnsServerResourceRecord -ZoneName corp.example.com -RRType A |
#     ForEach-Object { "$($_.HostName).corp.example.com,A,$($_.RecordData.IPv4Address)" }
set -euo pipefail
ZONE="${1:?зона}"
NS="${2:?DNS-сервер}"
OUT="data/raw/dns/$ZONE.csv"
mkdir -p "$(dirname "$OUT")"
{
  echo "name,type,value"
  dig @"$NS" "$ZONE" AXFR +noall +answer | awk '$4 == "A" { sub(/\.$/, "", $1); print $1 ",A," $5 }'
} > "$OUT.tmp"
[ "$(wc -l < "$OUT.tmp")" -gt 1 ] || { echo "AXFR вернул пусто — проверьте allow-transfer" >&2; rm -f "$OUT.tmp"; exit 1; }
mv "$OUT.tmp" "$OUT"
echo "$(($(wc -l < "$OUT") - 1)) записей → $OUT"
