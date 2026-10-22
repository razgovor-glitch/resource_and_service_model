#!/usr/bin/env bash
# Создаёт в кластере read-only ServiceAccount rsm-reader и kubeconfig для него.
#   usage: deploy/k8s/make-kubeconfig.sh <kube-context> <имя-кластера-в-модели> [out-file]
# Несколько кластеров потом склеиваются в один файл:
#   KUBECONFIG=kubeconfig-rsm-a:kubeconfig-rsm-b kubectl config view --flatten > ~/.kube/rsm
set -euo pipefail
CTX="${1:?kube-context}"
NAME="${2:?имя кластера, например k8s-prod-eu}"
OUT="${3:-kubeconfig-rsm-$NAME}"

kubectl --context "$CTX" apply -f "$(dirname "$0")/rsm-reader-rbac.yaml"

TOKEN=""
for _ in $(seq 1 30); do
  TOKEN=$(kubectl --context "$CTX" -n rsm-system get secret rsm-reader-token \
            -o jsonpath='{.data.token}' 2>/dev/null | base64 --decode || true)
  [ -n "$TOKEN" ] && break
  sleep 1
done
[ -n "$TOKEN" ] || { echo "токен не появился в rsm-system/rsm-reader-token" >&2; exit 1; }

CA=$(kubectl --context "$CTX" -n rsm-system get secret rsm-reader-token -o jsonpath='{.data.ca\.crt}')
CLUSTER_REF=$(kubectl config view -o jsonpath="{.contexts[?(@.name==\"$CTX\")].context.cluster}")
SERVER=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name==\"$CLUSTER_REF\")].cluster.server}")

umask 077
cat > "$OUT" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: $NAME
  cluster:
    server: $SERVER
    certificate-authority-data: $CA
users:
- name: rsm-reader@$NAME
  user:
    token: $TOKEN
contexts:
- name: $NAME
  context:
    cluster: $NAME
    user: rsm-reader@$NAME
current-context: $NAME
EOF
echo "готово: $OUT"
echo "проверка: kubectl --kubeconfig $OUT get nodes && kubectl --kubeconfig $OUT auth can-i get secrets -A  # должно быть 'no'"
