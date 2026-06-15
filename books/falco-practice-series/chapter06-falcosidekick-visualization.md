---
title: "第6回：Falcosidekick / UI可視化を入れてみる"
---

# Falcosidekick / UI可視化を入れてみる

前回（第5回）までで、Falcoのルールを書き、実運用に耐える設定を学びました。しかし、Falco単体では次のような課題があります。

- **アラートがログに埋もれる**（kubectl logsでしか見れない）
- **リアルタイムで気づけない**（Slackなどへの通知がない）
- **トレンド分析ができない**（過去のアラートを集計・可視化できない）
- **チームで共有しづらい**（各自がログを確認する必要がある）

この章では、**Falcosidekick**を導入して、これらの課題を解決します。

## この章で学ぶこと

1. **Falcosidekickの役割** - Falco単体との違いと必要性
2. **インストールと設定** - HelmでのFalco+Falcosidekick構築
3. **通知先の設定** - Slack/Teams/PagerDuty/Email連携
4. **Falcosidekick UI** - Webベースのアラート管理画面
5. **Grafana可視化** - PrometheusとGrafanaでトレンド分析
6. **実践シナリオ** - エンドツーエンドの運用フロー

---

## Falcosidekickとは

### 1.1 Falco単体の問題点

Falcoはデフォルトでは、検知したイベントを**標準出力**に出力するだけです。

```bash
# Falcoの標準出力例
20:14:23.456789123: Warning Shell spawned in container
  (user=root command=bash container_id=a3c4f21b pod=nginx-pod)
```

**問題**：

- [NG] ログは流れていってしまう（kubectl logsで見るしかない）
- [NG] リアルタイム通知がない
- [NG] 長期保存・検索できない
- [NG] 統計分析・可視化できない

### 1.2 Falcosidekickの役割

Falcosidekickは、Falcoのイベントを受け取り、**60種類以上の外部サービス**に転送するハブです。

```mermaid
flowchart LR
    Falco["Falco（Syscall/K8s Audit監視）"] -->|"gRPC/HTTP"| FSK["Falcosidekick（イベントルーティング）"]
    FSK --> Slack["Slack"]
    FSK --> PagerDuty["PagerDuty"]
    FSK --> Elasticsearch["Elasticsearch"]
    FSK --> Prometheus["Prometheus"]
    FSK --> SNS["AWS SNS/SQS"]
    FSK --> EventHub["Azure Event Hub"]
    FSK --> More["60+ outputs..."]
```

**解決できること**：

- [OK] リアルタイム通知（Slack/Teams/PagerDuty）
- [OK] 長期保存（Elasticsearch/Loki/S3）
- [OK] メトリクス化（Prometheus）
- [OK] 可視化（Grafana/Kibana）
- [OK] 自動対応（Webhook/Lambda/Cloud Functions）

### 1.3 アーキテクチャ全体像

```mermaid
flowchart TD
    subgraph Cluster["Kubernetes Cluster"]
        Pod1["Pod 1"]
        Pod2["Pod 2"]
        Pod3["Pod 3"]
        Falco["Falco DaemonSet（各ノードで実行）"]
        FSK["Falcosidekick（Deployment）"]
        UI["Falcosidekick UI"]
        Pod1 -->|"syscalls"| Falco
        Pod2 -->|"syscalls"| Falco
        Pod3 -->|"syscalls"| Falco
        Falco -->|"gRPC/HTTP"| FSK
        FSK --> UI
    end
    Browser["Webブラウザ"] --> UI
    FSK --> Slack["Slack"]
    FSK --> Prometheus["Prometheus"]
    FSK --> SNS["AWS SNS"]
```

---

## Falcosidekickのインストール

### 2.1 前提条件

```bash
# Kubernetesクラスタが必要（Kind/Minikube/GKE/EKS/AKS）
kubectl version --client

# Helmがインストール済みであること
helm version

# 既にFalcoがインストールされている場合は削除
helm uninstall falco -n falco 2>/dev/null || true
```

### 2.2 Helmを使った統合インストール

**Falco + Falcosidekick + Falcosidekick UIを一度にインストール**します。

```bash
# Falco Helm リポジトリを追加
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# falco namespaceを作成
kubectl create namespace falco

# values.yamlを作成
cat <<EOF > falco-values.yaml
# Falco本体の設定
driver:
  kind: modern_ebpf  # または ebpf

falco:
  grpc:
    enabled: true
  grpc_output:
    enabled: true
  json_output: true
  json_include_output_property: true

# Falcosidekickを有効化
falcosidekick:
  enabled: true
  config:
    slack:
      webhookurl: ""  # 後で設定
      minimumpriority: "warning"

    # Prometheusメトリクスを有効化
    prometheus:
      extralabels: "env:production"

  webui:
    enabled: true
    service:
      type: NodePort  # または LoadBalancer
      port: 2802

    # UIのデータベース（SQLite）
    redis:
      enabled: false  # 小規模環境ではSQLiteで十分

    # UIの保存期間設定
    ttl: 0  # 0 = 無制限（本番では適切な値を設定）

# カスタムルールを追加する場合
customRules:
  rules-custom.yaml: |-
    - rule: Custom Shell Detection
      desc: Detect shell in production namespace
      condition: >
        spawned_process and
        container and
        proc.name in (shell_binaries)
        and k8s.ns.name = "production"
      output: >
        Shell in production
        (user=%user.name cmd=%proc.cmdline
         pod=%k8s.pod.name container=%container.name)
      priority: WARNING
      tags: [production, shell]
EOF

# Falcoスタックをインストール
helm install falco falcosecurity/falco \
  --namespace falco \
  --values falco-values.yaml

# インストール確認
kubectl get pods -n falco
```

**期待される出力**：

```text
NAME                                      READY   STATUS    RESTARTS   AGE
falco-5zb8n                               2/2     Running   0          30s
falco-9xc7k                               2/2     Running   0          30s
falco-falcosidekick-6b9f5d5c7d-8xqwz      1/1     Running   0          30s
falco-falcosidekick-ui-7c8d6b5f9d-k2m4l   1/1     Running   0          30s
```

### 2.3 動作確認

```bash
# Falcoが起動していることを確認
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=10

# Falcosidekickが起動していることを確認
kubectl logs -n falco -l app.kubernetes.io/name=falcosidekick --tail=20

# UIにアクセス（NodePortの場合）
kubectl port-forward -n falco svc/falco-falcosidekick-ui 2802:2802
# ブラウザで http://localhost:2802 を開く
```

---

## 通知先の設定

### 3.1 Slack通知の設定

**ステップ1: Slack Incoming Webhookを作成**

1. https://api.slack.com/apps にアクセス
2. **Create New App** → **From scratch**
3. App名を入力（例: `Falco Alerts`）、ワークスペースを選択
4. **Incoming Webhooks** → **Activate Incoming Webhooks** をON
5. **Add New Webhook to Workspace** → チャンネルを選択（例: `#security-alerts`）
6. Webhook URLをコピー（`https://hooks.slack.com/services/...`）

**ステップ2: Helmのvaluesを更新**

```yaml
# falco-values.yaml
falcosidekick:
  enabled: true
  config:
    slack:
      webhookurl: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"
      minimumpriority: "warning"  # WARNING以上を通知
      messageformat: |
        {{- if .rule -}}
        :warning: *Falco Alert: {{ .rule }}*

        *Priority*: {{ .priority }}
        *Time*: {{ .time }}

        {{ if .output_fields }}
        *Details*:
        - User: {{ index .output_fields "user.name" | default "N/A" }}
        - Command: {{ index .output_fields "proc.cmdline" | default "N/A" }}
        - Container: {{ index .output_fields "container.name" | default "N/A" }}
        - Pod: {{ index .output_fields "k8s.pod.name" | default "N/A" }}
        - Namespace: {{ index .output_fields "k8s.ns.name" | default "N/A" }}
        {{ end }}

        *Full Output*:
        ```
        {{ .output }}
        ```
        {{- end -}}
      footer: "https://falco.org"
      icon: ":shield:"
      username: "Falco Security"
```

**ステップ3: Helmをアップグレード**

```bash
helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --values falco-values.yaml

# Falcosidekickが新しい設定を読み込んだことを確認
kubectl logs -n falco -l app.kubernetes.io/name=falcosidekick --tail=50 | grep slack
```

**ステップ4: テスト通知**

```bash
# テストPodでシェルを実行してアラートを発生させる
kubectl run test-alert --image=nginx --rm -it -- bash -c "cat /etc/shadow"

# 数秒後、Slackの #security-alerts にメッセージが届く
```

### 3.2 Microsoft Teams通知

```yaml
# falco-values.yaml
falcosidekick:
  config:
    teams:
      webhookurl: "https://outlook.office.com/webhook/YOUR-WEBHOOK-URL"
      minimumpriority: "warning"
      activityimage: "https://falco.org/img/falco-logo.png"
      outputformat: "all"
```

**Teams Webhook作成手順**：

1. Teamsで通知先チャンネルを開く
2. チャンネル名の右にある `...` → **Connectors**
3. **Incoming Webhook** を検索 → **Configure**
4. 名前を入力（例: `Falco Alerts`）
5. Webhook URLをコピー

### 3.3 PagerDuty連携（Critical アラート用）

```yaml
# falco-values.yaml
falcosidekick:
  config:
    pagerduty:
      routingkey: "YOUR_INTEGRATION_KEY"
      minimumpriority: "error"  # ERRORとCRITICALだけPagerDutyへ
      region: "us"  # または "eu"
```

**PagerDuty Integration Key取得手順**：

1. PagerDuty → **Services** → **New Service**
2. Integration Typeで **Events API V2** を選択
3. Integration Keyをコピー

**使い分け例**：

```yaml
falcosidekick:
  config:
    # 全てのWARNING以上をSlackへ
    slack:
      webhookurl: "..."
      minimumpriority: "warning"

    # CRITICALだけPagerDutyで即座に対応
    pagerduty:
      routingkey: "..."
      minimumpriority: "critical"

    # 全てのログをElasticsearchに保存
    elasticsearch:
      hostport: "http://elasticsearch:9200"
      index: "falco"
      minimumpriority: "info"
```

### 3.4 Email通知

```yaml
# falco-values.yaml
falcosidekick:
  config:
    smtp:
      hostport: "smtp.gmail.com:587"
      user: "your-email@gmail.com"
      password: "your-app-password"
      from: "falco-alerts@example.com"
      to: "security-team@example.com"
      minimumpriority: "error"
      format: "html"
```

### 3.5 対応する通知先一覧

| 通知先 | ユースケース | 設定の複雑さ | リアルタイム性 |
|--------|--------------|--------------|----------------|
| **Slack** | チーム内通知、日常監視 | ★ 低 | 即時 |
| **Teams** | Microsoft環境、企業内通知 | ★ 低 | 即時 |
| **PagerDuty** | 24/7オンコール対応 | ★★ 中 | 即時 |
| **Email** | 経営層への報告、監査 | ★ 低 | 即時〜数分 |
| **Webhook** | カスタム統合、Lambda連携 | ★★ 中 | 即時 |
| **AWS SNS/SQS** | AWS環境での自動対応 | ★★★ 高 | 即時 |
| **Elasticsearch** | ログ検索、長期保存 | ★★★ 高 | 数秒 |
| **Loki** | Grafana環境でのログ保存 | ★★ 中 | 数秒 |
| **S3** | 長期アーカイブ、監査証跡 | ★★ 中 | 分単位 |

---

## Falcosidekick UIの活用

### 4.1 UIへのアクセス

```bash
# NodePortの場合
kubectl port-forward -n falco svc/falco-falcosidekick-ui 2802:2802

# ブラウザで http://localhost:2802 を開く
```

**LoadBalancerの場合**（GKE/EKS/AKS）:

```yaml
# falco-values.yaml
falcosidekick:
  webui:
    enabled: true
    service:
      type: LoadBalancer
      annotations:
        # GKEの場合
        cloud.google.com/load-balancer-type: "Internal"
        # AWSの場合
        service.beta.kubernetes.io/aws-load-balancer-internal: "true"
```

```bash
# External IPを取得
kubectl get svc -n falco falco-falcosidekick-ui

# ブラウザでIPアドレス:2802にアクセス
```

### 4.2 ダッシュボードの見方

**メイン画面の構成**：

```
┌─────────────────────────────────────────────────┐
│  Falcosidekick UI                    [?] Search  │
├─────────────────────────────────────────────────┤
│                                                 │
│   Statistics                                  │
│  ┌───────────┬───────────┬───────────┐         │
│  │ Total     │ Critical  │ Warning   │         │
│  │ 1,234     │ 12        │ 456       │         │
│  └───────────┴───────────┴───────────┘         │
│                                                 │
│   Recent Events                               │
│  ┌─────────────────────────────────────────┐   │
│  │ [*] Shell spawned in container           │   │
│  │    Time: 2025-01-26 14:23:45           │   │
│  │    Pod: nginx-pod                       │   │
│  │    Namespace: production                │   │
│  ├─────────────────────────────────────────┤   │
│  │ [!]  Write to /etc in production         │   │
│  │    Time: 2025-01-26 14:22:10           │   │
│  │    Pod: api-server                      │   │
│  └─────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

### 4.3 フィルタリング機能

**Priority別フィルタ**：

- **Critical** - 即座に対応が必要な重大インシデント
- **Error** - 早急な対応が必要
- **Warning** - 監視・調査が必要
- **Notice** - 情報として記録
- **Info** - デバッグ用

**Rule別フィルタ**：

```text
検索ボックスに入力:
- "Shell spawned"      → シェル実行関連のみ表示
- "k8s.ns.name=prod"   → productionネームスペース のみ
- "priority=critical"  → Criticalのみ
```

**時間範囲フィルタ**：

- Last 15 minutes
- Last 1 hour
- Last 24 hours
- Custom range

### 4.4 イベント詳細画面

イベントをクリックすると詳細が表示されます：

```json
{
  "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "output": "Shell spawned in container (user=root cmd=bash container_id=a3c4f21b pod=nginx-pod)",
  "priority": "Warning",
  "rule": "Shell spawned in container",
  "time": "2025-01-26T14:23:45.123456Z",
  "output_fields": {
    "container.id": "a3c4f21b",
    "container.name": "nginx",
    "k8s.ns.name": "production",
    "k8s.pod.name": "nginx-pod",
    "proc.cmdline": "bash",
    "user.name": "root"
  },
  "source": "syscall",
  "tags": ["container", "shell", "mitre_execution"]
}
```

**有用な使い方**：

1. **インシデント調査** - 「いつ、誰が、どのPodで」を即座に把握
2. **パターン分析** - 同じルールが頻発していないか確認
3. **False Positive特定** - 正常動作なのに検知されているルールを発見

---

## Prometheusとの連携

### 5.1 Prometheusメトリクスの有効化

Falcosidekickは自動的にPrometheusメトリクスを`/metrics`エンドポイントで公開します。

```yaml
# falco-values.yaml
falcosidekick:
  config:
    prometheus:
      extralabels: "env:production,cluster:main"

  # ServiceMonitorを自動作成（Prometheus Operatorを使用している場合）
  serviceMonitor:
    enabled: true
    interval: 30s
```

**公開されるメトリクス**：

```text
# Falcoイベント総数
falco_events_total{priority="warning", rule="Shell spawned in container"} 42

# 通知先別の送信成功数
falcosidekick_outputs_total{destination="slack", status="success"} 38
falcosidekick_outputs_total{destination="slack", status="error"} 4

# レイテンシー
falcosidekick_request_duration_seconds_bucket{le="0.1"} 35
```

### 5.2 Grafanaダッシュボードのインポート

**公式ダッシュボードをインポート**：

1. Grafanaにログイン
2. **+ → Import**
3. Grafana.com Dashboard ID を入力: **11914**
4. **Load** → データソースでPrometheusを選択 → **Import**

**または、直接URLからインポート**：

```text
https://grafana.com/grafana/dashboards/11914-falco-dashboard/
```

### 5.3 カスタムダッシュボードの作成

**Prometheus クエリ例**：

```promql
# 直近1時間のアラート数
sum(increase(falco_events_total[1h])) by (rule)

# Priority別の割合
sum(falco_events_total) by (priority)

# 最も頻繁に検知されるルール Top 10
topk(10, sum(rate(falco_events_total[5m])) by (rule))

# 特定namespace のアラート数
sum(falco_events_total{k8s_ns_name="production"})

# アラート発生率（per minute）
rate(falco_events_total[5m]) * 60
```

**Grafana Panel設定例**：

```json
{
  "title": "Falco Alerts by Priority (Last 24h)",
  "targets": [
    {
      "expr": "sum(increase(falco_events_total[24h])) by (priority)"
    }
  ],
  "type": "piechart"
}
```

---

## Elasticsearch + Kibanaでの可視化

### 6.1 Elasticsearchへの送信設定

```yaml
# falco-values.yaml
falcosidekick:
  config:
    elasticsearch:
      hostport: "http://elasticsearch:9200"
      index: "falco"
      type: "_doc"
      minimumpriority: "info"

      # 認証が必要な場合
      # username: "elastic"
      # password: "changeme"

      # AWS Elasticsearch Service
      # customheaders:
      #   - "X-Custom-Header: value"
```

### 6.2 Kibanaでのインデックスパターン作成

```bash
# Kibana UIで以下を実行:
# Management → Index Patterns → Create index pattern
# Index pattern name: "falco*"
# Time field: "@timestamp" または "time"
# Create index pattern
```

### 6.3 Kibana Discover でのログ検索

**検索クエリ例**：

```text
# Criticalアラートだけ
priority: "Critical"

# 特定のルール
rule: "Shell spawned in container"

# 特定のnamespace
output_fields.k8s.ns.name: "production"

# 過去1時間のWarning以上
priority: ("Warning" OR "Error" OR "Critical") AND time:[now-1h TO now]

# 特定のコンテナイメージ
output_fields.container.image.repository: "*nginx*"
```

---

## 実践：エンドツーエンドの運用フロー

### シナリオ: 本番環境でのSSH実行を検知・対応

**ステップ1: カスタムルールを作成**

```yaml
# custom-rules.yaml
- rule: SSH Execution in Production
  desc: Detect SSH client usage in production namespace
  condition: >
    spawned_process and
    container and
    proc.name in (ssh, scp, sftp)
    and k8s.ns.name = "production"
  output: >
    SSH client executed in production environment
    (user=%user.name command=%proc.cmdline
     pod=%k8s.pod.name container=%container.name
     image=%container.image.repository)
  priority: ERROR
  tags: [production, ssh, network, suspicious]
```

**ステップ2: Helmで適用**

```bash
# custom-rules.yaml をConfigMapに追加
kubectl create configmap falco-custom-rules \
  --from-file=custom-rules.yaml \
  -n falco

# values.yamlで参照
helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --set customRules."custom-rules\.yaml"="$(cat custom-rules.yaml)"
```

**ステップ3: アラートをトリガー**

```bash
# テスト用Podをデプロイ
kubectl run test-ssh -n production --image=alpine --rm -it -- sh

# Pod内でSSHクライアントをインストール・実行
apk add openssh-client
ssh test@example.com
```

**ステップ4: Slack通知を確認**

数秒以内にSlackに次のようなメッセージが届きます：

```text
[!] Falco Alert: SSH Execution in Production

Priority: ERROR
Time: 2025-01-26 15:30:45

Details:
- User: root
- Command: ssh test@example.com
- Container: test-ssh
- Pod: test-ssh
- Namespace: production

Full Output:
SSH client executed in production environment (user=root command=ssh test@example.com pod=test-ssh container=test-ssh image=alpine)
```

**ステップ5: Falcosidekick UIで詳細確認**

1. ブラウザで Falcosidekick UI を開く
2. 最新イベントに「SSH Execution in Production」が表示される
3. クリックして詳細JSONを確認
4. 同じPodからの他のアラートがないか確認

**ステップ6: Grafanaでトレンド確認**

1. Grafanaダッシュボードを開く
2. 「SSH Execution」ルールの発生頻度を確認
3. 過去7日間でこのルールが初めてトリガーされたことを確認
4. production namespaceでの異常なアクティビティパターンを分析

**ステップ7: 対応とエスカレーション**

```bash
# Podの詳細を調査
kubectl describe pod test-ssh -n production

# 最近のログを確認
kubectl logs test-ssh -n production --tail=100

# 不正なアクティビティと判断した場合、Podを削除
kubectl delete pod test-ssh -n production

# ネットワークポリシーで将来の外部SSH接続をブロック
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-ssh-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector: {}
    ports:
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 80
  # SSH (port 22) はブロック
EOF
```

---

## 高度な設定

### 8.1 複数環境での通知先分離

```yaml
# falco-values.yaml
falcosidekick:
  config:
    # 本番環境のCriticalはPagerDuty
    pagerduty:
      routingkey: "prod-critical-key"
      minimumpriority: "critical"
      customfields:
        - name: "k8s.ns.name"
          value: "production"

    # ステージング環境のWarningはSlack
    slack:
      webhookurl: "https://hooks.slack.com/services/..."
      minimumpriority: "warning"
      customfields:
        - name: "k8s.ns.name"
          value: "staging"
```

### 8.2 Webhookを使ったカスタム自動対応

```yaml
# falco-values.yaml
falcosidekick:
  config:
    webhook:
      address: "http://my-automation-service:8080/falco-events"
      minimumpriority: "error"
      customheaders:
        - "Authorization: Bearer SECRET_TOKEN"
```

**カスタム自動対応サービスの例**（Python Flask）:

```python
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/falco-events', methods=['POST'])
def handle_falco_event():
    event = request.json

    # Criticalアラートの場合、該当Podを自動削除
    if event['priority'] == 'Critical':
        namespace = event['output_fields'].get('k8s.ns.name')
        pod_name = event['output_fields'].get('k8s.pod.name')

        if namespace and pod_name:
            subprocess.run([
                'kubectl', 'delete', 'pod', pod_name, '-n', namespace
            ])

            return {'status': 'pod_deleted', 'pod': pod_name}, 200

    return {'status': 'no_action'}, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

### 8.3 AWS SNS経由でのLambda連携

```yaml
# falco-values.yaml
falcosidekick:
  config:
    aws:
      region: "us-east-1"
      accesskeyid: "AKIAIOSFODNN7EXAMPLE"
      secretaccesskey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      sns:
        topicarn: "arn:aws:sns:us-east-1:123456789012:falco-alerts"
        minimumpriority: "warning"
```

**Lambda関数例**（Node.js）:

```javascript
exports.handler = async (event) => {
    const message = JSON.parse(event.Records[0].Sns.Message);

    // SlackやJIRAにチケット作成など
    if (message.priority === 'Critical') {
        // JIRAチケット作成APIを呼び出し
        await createJiraTicket({
            summary: `[SECURITY] ${message.rule}`,
            description: message.output,
            priority: 'Highest'
        });
    }

    return { statusCode: 200 };
};
```

---

## トラブルシューティング

### 9.1 Slack通知が届かない

**原因1: Webhook URLが間違っている**

```bash
# Falcosidekickのログを確認
kubectl logs -n falco -l app.kubernetes.io/name=falcosidekick | grep -i slack

# エラー例:
# ERROR: Failed to send to Slack: 404 Not Found
```

**解決策**:

```bash
# Secretを確認
kubectl get secret -n falco falco-falcosidekick -o jsonpath='{.data.config\.yaml}' | base64 -d | grep webhookurl

# 正しいURLに更新
helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --set falcosidekick.config.slack.webhookurl="正しいURL"
```

**原因2: minimumpriorityが高すぎる**

```yaml
# "error"に設定されている場合、"warning"は通知されない
falcosidekick:
  config:
    slack:
      minimumpriority: "error"  # これが原因
```

**解決策**: `minimumpriority: "warning"` に変更

### 9.2 Falcosidekick UIに何も表示されない

**原因: FalcoとFalcosidekickの接続が切れている**

```bash
# Falcoログを確認
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep -i "grpc\|sidekick"

# エラー例:
# ERROR: Failed to send event to Falcosidekick: connection refused
```

**解決策**:

```bash
# Falcosidekick Serviceを確認
kubectl get svc -n falco falco-falcosidekick

# FalcoのgRPC設定を確認
kubectl get cm -n falco falco -o yaml | grep -A 10 "grpc_output"
```

### 9.3 メトリクスがPrometheusに表示されない

```bash
# ServiceMonitorが作成されているか確認
kubectl get servicemonitor -n falco

# Prometheus Operatorのログを確認
kubectl logs -n monitoring -l app.kubernetes.io/name=prometheus-operator

# 手動でメトリクスエンドポイントを確認
kubectl port-forward -n falco svc/falco-falcosidekick 2801:2801
curl http://localhost:2801/metrics
```

---

## まとめ

この章では、Falcosidekickを使った通知と可視化について学びました。

### 学んだこと

[OK] **Falcosidekickの役割** - Falcoイベントを60+の外部サービスへルーティング
[OK] **通知設定** - Slack/Teams/PagerDuty/Email連携
[OK] **Falcosidekick UI** - Webベースのリアルタイムアラート管理
[OK] **Prometheus/Grafana** - メトリクス化とトレンド分析
[OK] **Elasticsearch/Kibana** - 長期保存と高度なログ検索
[OK] **実践運用フロー** - 検知→通知→調査→対応の一連の流れ

### アーキテクチャのベストプラクティス

```text
推奨構成:
- Falco (DaemonSet): 全ノードでイベント検知
- Falcosidekick (Deployment): イベントルーティング
- Falcosidekick UI (Deployment): リアルタイム確認
- Prometheus: メトリクス収集
- Grafana: 可視化・ダッシュボード
- Elasticsearch: 長期保存・検索
- Slack: チーム通知
- PagerDuty: Critical対応
```

### 次のステップ

- **第7回**：Kubernetes Audit LogとFalcoの連携
- **第8回**：CI/CDパイプラインへの組み込み
- **第9回**：本番環境へのデプロイ設計

---

## 参考資料

- [Falcosidekick Documentation](https://github.com/falcosecurity/falcosidekick)
- [Falcosidekick UI](https://github.com/falcosecurity/falcosidekick-ui)
- [Falcosidekick Helm Chart](https://github.com/falcosecurity/charts/tree/master/charts/falcosidekick)
- [Grafana Dashboard 11914](https://grafana.com/grafana/dashboards/11914)
- [Supported Outputs List](https://github.com/falcosecurity/falcosidekick#outputs)
