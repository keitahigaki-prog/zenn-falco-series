---
title: "第5回：Falcoのルールを書く（中級編）- 実運用に寄せる"
---

# Falcoのルールを書く（中級編）- 実運用に寄せる

前回（第4回）では、Falcoルールの基本構文と簡単なルールの書き方を学びました。しかし、実際の本番環境でFalcoを運用すると、次のような課題に直面します。

- **アラートが多すぎる**（正常な動作でも検知してしまう）
- **特定のワークロードだけ例外にしたい**（CI/CDジョブは許可など）
- **ルール変更の影響範囲が読めない**（変更したら大量アラートが発生）
- **チームメンバーとルールを共有・管理できない**

この章では、実運用に耐える**中級レベルのFalcoルール**を書くための技術を習得します。

## この章で学ぶこと

1. **スコープ限定** - namespace/labelsを使った検知対象の絞り込み
2. **例外処理** - 特定workloadの除外方法（exception機能）
3. **ノイズ削減** - アラート疲れを防ぐ設計パターン
4. **影響範囲テスト** - ルール変更の安全な適用方法
5. **実運用パターン** - 本番で使える5つの実践例

---

## 1. なぜ実運用では「例外」が必要なのか

### 1.1 典型的な問題：正常動作が検知される

第4回で作成したシンプルなルールをそのまま本番環境に適用すると、こんな問題が起こります。

```yaml
- rule: Shell Spawned in Container
  desc: Detect shell execution in containers
  condition: >
    spawned_process and
    container and
    proc.name in (shell_binaries)
  output: Shell spawned (user=%user.name cmd=%proc.cmdline container=%container.name)
  priority: WARNING
```

**問題点**：

- **CI/CDジョブ**：GitLab Runner/Jenkins Agentがシェルスクリプトでビルドするとアラートだらけ
- **監視エージェント**：Datadog/New Relicのコンテナがヘルスチェックでbashを実行
- **管理ツール**：kubectl debugやkubectl execで正当な理由でシェルを起動

これらは**正常な動作**なのに、すべて検知されてしまいます。

### 1.2 解決策：スコープ限定 + 例外処理

```yaml
- rule: Shell Spawned in Container (Production Only)
  desc: Detect suspicious shell execution in production workloads
  condition: >
    spawned_process and
    container and
    proc.name in (shell_binaries)
    and k8s.ns.name in (production_namespaces)
    and not k8s.deployment.label.allow-shell = "true"
    and not k8s.deployment.name in (ci_deployments)
  output: >
    Suspicious shell spawned in production
    (user=%user.name cmd=%proc.cmdline
     namespace=%k8s.ns.name pod=%k8s.pod.name
     container=%container.name)
  priority: WARNING
  tags: [production, shell, suspicious]
```

**改善点**：

1. `k8s.ns.name in (production_namespaces)` - 本番namespaceだけ検知
2. `not k8s.deployment.label.allow-shell = "true"` - ラベルでの除外
3. `not k8s.deployment.name in (ci_deployments)` - CI/CD除外

---

## 2. スコープの限定テクニック

### 2.1 namespaceによる限定

**ユースケース**：本番環境（production/prod-*）だけ厳格に監視したい

```yaml
- list: production_namespaces
  items: [production, prod-api, prod-web, prod-database]

- rule: Write to /etc in Production
  desc: Detect writes to /etc directory in production namespaces
  condition: >
    open_write and
    container and
    fd.name startswith /etc/
    and k8s.ns.name in (production_namespaces)
  output: >
    Write to /etc in production namespace
    (file=%fd.name namespace=%k8s.ns.name
     pod=%k8s.pod.name container=%container.name
     command=%proc.cmdline user=%user.name)
  priority: ERROR
  tags: [filesystem, production, compliance]
```

**動作確認**：

```bash
# production namespaceで検知される
kubectl run test-prod -n production --image=nginx --rm -it -- bash -c "echo test > /etc/test.conf"

# development namespaceでは検知されない
kubectl run test-dev -n development --image=nginx --rm -it -- bash -c "echo test > /etc/test.conf"
```

### 2.2 labelsによる限定

**ユースケース**：特定のラベルを持つPodだけ監視対象にする

```yaml
- rule: Network Tool Execution in Critical Workloads
  desc: Detect network tools in pods labeled as critical
  condition: >
    spawned_process and
    container and
    proc.name in (network_tools)
    and k8s.pod.label.security-tier = "critical"
  output: >
    Network tool executed in critical workload
    (tool=%proc.name command=%proc.cmdline
     pod=%k8s.pod.name namespace=%k8s.ns.name
     labels=%k8s.pod.labels)
  priority: WARNING
  tags: [network, critical, compliance]

- list: network_tools
  items: [nc, ncat, netcat, nmap, tcpdump, wireshark, tshark]
```

**Pod定義例**：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: payment-service
  namespace: production
  labels:
    security-tier: critical  # このラベルで検知対象になる
spec:
  containers:
  - name: app
    image: payment:v1.0
```

### 2.3 複数条件の組み合わせ

**ユースケース**：「本番」かつ「インターネット向け」のPodだけ厳格に監視

```yaml
- rule: Outbound Connection from Public-Facing Pods
  desc: Detect unexpected outbound connections from internet-facing workloads
  condition: >
    outbound and
    container and
    k8s.ns.name in (production_namespaces)
    and k8s.pod.label.exposure = "public"
    and not fd.sip.name in (allowed_external_endpoints)
  output: >
    Outbound connection from public-facing pod
    (destination=%fd.rip:%fd.rport
     pod=%k8s.pod.name namespace=%k8s.ns.name
     command=%proc.cmdline)
  priority: ERROR
  tags: [network, egress, production, public]

- list: allowed_external_endpoints
  items: [
    "api.stripe.com",
    "api.sendgrid.com",
    "*.amazonaws.com",
    "*.cloudfront.net"
  ]
```

---

## 3. 例外（Exception）の作り方

Falcoでは、**exception機能**を使って例外を綺麗に管理できます。

### 3.1 例外の基本構文

```yaml
- rule: Terminal Shell in Container
  desc: Detect interactive shell in containers
  condition: >
    spawned_process and
    container and
    proc.name in (shell_binaries)
  output: Shell executed (user=%user.name cmd=%proc.cmdline container=%container.name)
  priority: WARNING
  exceptions:
    - name: authorized_admin_shells
      fields: [user.name, k8s.ns.name, container.image.repository]
      comps: [=, =, startswith]
      values:
        - [admin-user, kube-system, k8s.gcr.io]
        - [operator, monitoring, prom/]
```

**解説**：

- `fields`: 例外判定に使うフィールド
- `comps`: 比較演算子（`=`, `!=`, `in`, `startswith` など）
- `values`: 例外として許可する値の組み合わせ

この例では：
- `admin-user`が`kube-system`で`k8s.gcr.io`イメージを使うとき
- `operator`が`monitoring`で`prom/`で始まるイメージを使うとき

はアラートを出しません。

### 3.2 workloadごとの例外

**ユースケース**：CI/CDジョブだけroot実行を許可する

```yaml
- rule: Run as Root User
  desc: Detect processes running as root (UID 0)
  condition: >
    spawned_process and
    container and
    user.uid = 0
    and not container.image.repository in (trusted_base_images)
  output: >
    Process running as root
    (user=%user.name uid=%user.uid
     command=%proc.cmdline
     container=%container.name image=%container.image.repository)
  priority: WARNING
  exceptions:
    - name: ci_cd_jobs
      fields: [k8s.ns.name, k8s.deployment.name]
      comps: [=, in]
      values:
        - [gitlab-runner, [runner-docker, runner-shell]]
        - [jenkins, [jenkins-agent, jenkins-master]]
        - [tekton-pipelines, [tekton-triggers-controller]]

- list: trusted_base_images
  items: [
    "docker.io/library/nginx",
    "docker.io/library/redis",
    "docker.io/library/postgres"
  ]
```

**テスト方法**：

```bash
# gitlab-runner namespaceでは検知されない
kubectl run test -n gitlab-runner --image=ubuntu -- sleep 3600

# 通常のnamespaceでは検知される
kubectl run test -n default --image=ubuntu -- sleep 3600
```

### 3.3 時間帯による例外

**ユースケース**：メンテナンス時間帯だけ許可する

```yaml
- macro: maintenance_window
  condition: >
    (evt.hour >= 2 and evt.hour < 4)

- rule: Package Manager Execution
  desc: Detect package manager usage (apt/yum/apk)
  condition: >
    spawned_process and
    container and
    proc.name in (package_managers)
    and not maintenance_window
  output: >
    Package manager executed outside maintenance window
    (tool=%proc.name command=%proc.cmdline
     time=%evt.time container=%container.name)
  priority: WARNING
  tags: [software, maintenance, compliance]

- list: package_managers
  items: [apt, apt-get, yum, dnf, apk, zypper, rpm, dpkg]
```

**動作確認**：

```bash
# 2:00-4:00の間は検知されない（UTC時刻）
date  # 現在時刻を確認
kubectl exec -it test-pod -- apt-get update
```

### 3.4 ユーザーによる例外

**ユースケース**：SREチームのメンバーだけkubectl execを許可

```yaml
- rule: kubectl Exec into Pod
  desc: Detect kubectl exec command execution
  condition: >
    spawned_process and
    container and
    proc.pname = "runc"
    and proc.name in (shell_binaries)
    and k8s_audit.verb = "create"
    and k8s_audit.objectRef.resource = "pods"
    and k8s_audit.objectRef.subresource = "exec"
  output: >
    kubectl exec executed
    (user=%k8s_audit.user.username
     pod=%k8s_audit.objectRef.name
     namespace=%k8s_audit.objectRef.namespace
     command=%proc.cmdline)
  priority: NOTICE
  exceptions:
    - name: authorized_sre_team
      fields: [k8s_audit.user.username, k8s.ns.name]
      comps: [in, not in]
      values:
        - [[sre-alice, sre-bob, sre-carol], [production, prod-database]]
```

**解説**：
- SREメンバー（alice/bob/carol）の`kubectl exec`は記録するが警告しない
- ただし`production`/`prod-database`への実行は例外なく記録

---

## 4. 実運用パターン集

### パターン1：CI/CDジョブの例外管理

**シナリオ**：GitLab RunnerがDockerビルドでroot権限を使う

```yaml
- rule: Privileged Container Started
  desc: Detect containers running in privileged mode
  condition: >
    container_started and
    container.privileged = true
  output: >
    Privileged container started
    (container=%container.name image=%container.image.repository
     namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: WARNING
  tags: [container, security, privileged]
  exceptions:
    - name: gitlab_dind_runners
      fields: [k8s.ns.name, container.image.repository]
      comps: [=, startswith]
      values:
        - [gitlab-runner, docker.io/gitlab/gitlab-runner]
        - [gitlab-runner, docker.io/library/docker]  # DinD (Docker-in-Docker)
```

**設定ファイル構成**：

```yaml
# /etc/falco/falco_rules.local.yaml
- list: ci_namespaces
  items: [gitlab-runner, jenkins, tekton-pipelines, argocd]
  override:
    items: append

- rule: Privileged Container Started
  append: true
  exceptions:
    - name: additional_ci_tools
      fields: [k8s.ns.name]
      comps: [in]
      values:
        - [ci_namespaces]
```

### パターン2：kubectl exec検知とSlack通知

**シナリオ**：本番Podへの`kubectl exec`を全て記録・通知したい

```yaml
- rule: Interactive Shell via kubectl exec
  desc: Detect interactive shell sessions via kubectl exec in production
  condition: >
    spawned_process and
    container and
    proc.name in (shell_binaries)
    and proc.pname = "runc"
    and k8s.ns.name in (production_namespaces)
  output: >
    Interactive shell session started via kubectl exec
    (user=%user.name
     pod=%k8s.pod.name
     namespace=%k8s.ns.name
     container=%container.name
     command=%proc.cmdline
     parent_process=%proc.pname)
  priority: NOTICE
  tags: [shell, kubectl, audit, production]
```

**Falcosidekick設定** (次章で詳細解説)：

```yaml
# falcosidekick config.yaml
slack:
  webhookurl: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  minimumpriority: "notice"
  messageformat: |
    🚨 kubectl exec detected in production!

    • User: {{.user.name}}
    • Pod: {{.k8s.pod.name}}
    • Namespace: {{.k8s.ns.name}}
    • Command: {{.proc.cmdline}}
    • Time: {{.output_fields.evt.time}}
```

### パターン3：機密ファイルアクセスの段階的検知

**シナリオ**：`/etc/shadow`への読み取りを段階的に厳格化

```yaml
# Stage 1: 全環境で情報収集（7日間）
- rule: Shadow File Read - Audit Phase
  desc: Collect baseline data for /etc/shadow reads
  condition: >
    open_read and
    fd.name = /etc/shadow
  output: >
    /etc/shadow read detected [AUDIT]
    (user=%user.name command=%proc.cmdline
     container=%container.name namespace=%k8s.ns.name)
  priority: INFO
  tags: [audit, filesystem, shadow]
  enabled: true

# Stage 2: 本番のみWARNING（14日間）
- rule: Shadow File Read - Production Warning
  desc: Warn on /etc/shadow reads in production
  condition: >
    open_read and
    fd.name = /etc/shadow
    and k8s.ns.name in (production_namespaces)
    and not container.image.repository in (system_containers)
  output: >
    /etc/shadow read in production [WARNING]
    (user=%user.name command=%proc.cmdline
     container=%container.name namespace=%k8s.ns.name
     image=%container.image.repository)
  priority: WARNING
  tags: [production, filesystem, shadow]
  enabled: true

# Stage 3: 本番でERROR + 自動対応
- rule: Shadow File Read - Production Block
  desc: Critical alert for /etc/shadow reads in production
  condition: >
    open_read and
    fd.name = /etc/shadow
    and k8s.ns.name in (production_namespaces)
    and not container.image.repository in (system_containers)
  output: >
    CRITICAL: /etc/shadow read in production
    (user=%user.name command=%proc.cmdline
     container=%container.name namespace=%k8s.ns.name
     image=%container.image.repository pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [production, filesystem, shadow, incident]
  enabled: false  # 準備が整ってから有効化

- list: system_containers
  items: [
    "k8s.gcr.io/kube-apiserver",
    "quay.io/prometheus/node-exporter",
    "datadog/agent"
  ]
```

**段階的ロールアウト**：

1. **Week 1-2**: `Audit Phase`を有効化してベースライン収集
2. **Week 3-4**: データ分析して例外リストを作成
3. **Week 5-6**: `Production Warning`を有効化して監視
4. **Week 7+**: `Production Block`を有効化して自動対応

### パターン4：暗号通貨マイニング検知

**シナリオ**：コンテナ内でのマイニングツール実行を検知

```yaml
- list: mining_tools
  items: [
    xmrig, xmr-stak, cpuminer, ethminer, cgminer, bfgminer,
    minerd, ccminer, t-rex, phoenixminer, nbminer, gminer
  ]

- list: mining_domains
  items: [
    "*.pool.minexmr.com",
    "*.supportxmr.com",
    "*.miningpoolhub.com",
    "*.nanopool.org",
    "*.2miners.com",
    "*.f2pool.com"
  ]

- rule: Cryptocurrency Mining Activity
  desc: Detect cryptocurrency mining processes or connections
  condition: >
    (spawned_process and proc.name in (mining_tools))
    or
    (outbound and fd.sip.name in (mining_domains))
  output: >
    Cryptocurrency mining detected
    (process=%proc.name command=%proc.cmdline
     connection=%fd.rip:%fd.rport
     container=%container.name pod=%k8s.pod.name
     namespace=%k8s.ns.name image=%container.image.repository)
  priority: CRITICAL
  tags: [malware, mining, security, incident]
```

**自動対応との連携**：

```yaml
# Falcosidekick Response Engine設定
apiVersion: falco.org/v1alpha1
kind: Response
metadata:
  name: kill-mining-pod
spec:
  match:
    rules:
      - Cryptocurrency Mining Activity
    priority: CRITICAL
  actions:
    - action: delete
      parameters:
        namespace: "{{ .k8s.ns.name }}"
        podName: "{{ .k8s.pod.name }}"
    - action: notify
      parameters:
        channel: "#security-incidents"
        message: "Mining pod deleted: {{ .k8s.pod.name }}"
```

### パターン5：コンプライアンス要件（PCI-DSS）

**シナリオ**：PCI-DSS Requirement 10.2.5 - ログファイルへの不正アクセス

```yaml
- list: log_files
  items: [
    /var/log,
    /var/log/audit,
    /var/log/syslog,
    /var/log/secure,
    /var/log/messages
  ]

- list: authorized_log_readers
  items: [
    fluentd, filebeat, logstash, vector, promtail,
    datadog-agent, splunk-forwarder
  ]

- rule: PCI-DSS 10.2.5 - Unauthorized Log Access
  desc: >
    Detect unauthorized access to system logs
    (PCI-DSS Requirement 10.2.5: Initialization, stopping, or pausing of audit logs)
  condition: >
    (open_write or open_read) and
    container and
    fd.name pmatch (log_files) and
    not proc.name in (authorized_log_readers)
    and not container.image.repository in (system_containers)
  output: >
    PCI-DSS Violation: Unauthorized log file access
    (file=%fd.name user=%user.name uid=%user.uid
     process=%proc.name command=%proc.cmdline
     container=%container.name image=%container.image.repository
     namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: ERROR
  tags: [pci-dss, compliance, filesystem, audit, logs]
```

---

## 5. ノイズ削減戦略

### 5.1 ベースラインの作成

**手順1：ログモードで運用開始**

```yaml
# falco.yaml
rules_file:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml
  - /etc/falco/baseline_collection.yaml  # ベースライン収集用

json_output: true
json_include_output_property: true
log_level: info

# 全てのルールをINFOレベルで記録
priority: INFO
```

**手順2：データ収集スクリプト**

```bash
#!/bin/bash
# collect_baseline.sh

# 1週間分のFalcoログを集約
kubectl logs -n falco -l app=falco --since=168h > falco_baseline.json

# 頻度の高いイベントをカウント
cat falco_baseline.json | \
  jq -r '.rule' | \
  sort | uniq -c | sort -rn > rule_frequency.txt

# コンテナイメージごとの集計
cat falco_baseline.json | \
  jq -r '"\(.rule)|\(.output_fields["container.image.repository"])"' | \
  sort | uniq -c | sort -rn > rule_by_image.txt

echo "=== Top 20 Noisy Rules ==="
head -20 rule_frequency.txt

echo "=== Top Noisy Images ==="
head -20 rule_by_image.txt
```

**出力例**：

```
=== Top 20 Noisy Rules ===
  12543 Shell Spawned in Container
   8921 Write to /etc directory
   6742 Network Tool Execution
   4521 Package Manager Execution
   2314 Read Sensitive File
```

### 5.2 段階的なルール適用

**Phase 1: Information Gathering（1-2週間）**

```yaml
- rule: Shell Spawned in Container
  priority: INFO  # 全て記録、アラートなし
  enabled: true

- rule: Write to /etc directory
  priority: INFO
  enabled: true
```

**Phase 2: Selective Warning（2-4週間）**

```yaml
- rule: Shell Spawned in Container
  priority: WARNING  # 本番のみ警告
  condition: >
    spawned_process and
    container and
    proc.name in (shell_binaries)
    and k8s.ns.name in (production_namespaces)
  enabled: true
```

**Phase 3: Production Enforcement（4週間以降）**

```yaml
- rule: Shell Spawned in Container
  priority: ERROR  # 本番で厳格に検知
  condition: >
    spawned_process and
    container and
    proc.name in (shell_binaries)
    and k8s.ns.name in (production_namespaces)
    and not (正当な例外条件)
  enabled: true
```

### 5.3 アラート疲れを防ぐ設計パターン

**パターンA：レート制限**

```yaml
# Falcosidekickでレート制限
customfields:
  ratelimit_key: "{{ .rule }}:{{ .k8s.ns.name }}:{{ .k8s.pod.name }}"
  ratelimit_duration: "5m"  # 同じPodから5分間に1回だけ通知
```

**パターンB：集約アラート**

```yaml
# 同一ルールを10分ごとにサマリー通知
slack:
  minimumpriority: "warning"
  messageformat: |
    📊 Falco Alert Summary (last 10 minutes)

    • Rule: {{.rule}}
    • Count: {{.count}}
    • Affected Pods: {{.pods | join ", "}}
    • Namespaces: {{.namespaces | uniq | join ", "}}
```

**パターンC：重要度による通知先分離**

```yaml
# falcosidekick config
slack:
  webhookurl: "https://hooks.slack.com/services/CRITICAL_CHANNEL"
  minimumpriority: "error"

teams:
  webhookurl: "https://outlook.office.com/webhook/WARNING_CHANNEL"
  minimumpriority: "warning"

elasticsearch:
  hostport: "http://elasticsearch:9200"
  index: "falco"
  minimumpriority: "info"  # 全てElasticsearchには記録
```

---

## 6. 変更の影響範囲テスト

### 6.1 テスト環境での検証

**1. 専用テストnamespaceを作成**

```bash
kubectl create namespace falco-test
kubectl label namespace falco-test falco-testing=true
```

**2. テスト用Falco設定**

```yaml
# falco-test-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-test-rules
  namespace: falco-test
data:
  test_rules.yaml: |
    - rule: Test Rule - Shell in Container
      desc: Testing shell detection in falco-test namespace
      condition: >
        spawned_process and
        container and
        proc.name in (shell_binaries)
        and k8s.ns.name = "falco-test"
      output: >
        [TEST] Shell detected
        (pod=%k8s.pod.name command=%proc.cmdline)
      priority: WARNING
      tags: [test]
```

**3. 影響範囲の確認**

```bash
# テストPodをデプロイ
kubectl run test-pod -n falco-test --image=nginx --rm -it -- bash

# Falcoログで検知を確認
kubectl logs -n falco -l app=falco | grep "TEST"

# 他のnamespaceに影響がないことを確認
kubectl run prod-pod -n production --image=nginx --rm -it -- bash
# ↑ これは[TEST]タグで検知されないはず
```

### 6.2 カナリアデプロイメント

**シナリオ**：新しいルールセットを段階的にロールアウト

```yaml
# 10%のFalco Podだけ新ルールを適用
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco-canary
  namespace: falco
spec:
  selector:
    matchLabels:
      app: falco
      version: canary
  template:
    metadata:
      labels:
        app: falco
        version: canary
    spec:
      nodeSelector:
        falco-canary: "true"  # 特定ノードだけ
      containers:
      - name: falco
        image: falcosecurity/falco:0.37.0
        volumeMounts:
        - name: rules-canary
          mountPath: /etc/falco/rules.d/
      volumes:
      - name: rules-canary
        configMap:
          name: falco-rules-canary  # 新しいルールセット
```

**ロールアウト手順**：

```bash
# 1. カナリアノードをラベリング（全体の10%）
kubectl label nodes node-1 node-2 falco-canary=true

# 2. カナリア用ルールをデプロイ
kubectl apply -f falco-rules-canary.yaml

# 3. 24時間監視
kubectl logs -n falco -l version=canary | grep -i error

# 4. 問題なければ全体にロールアウト
kubectl label nodes --all falco-canary=true
kubectl rollout restart daemonset/falco -n falco
```

### 6.3 ロールバック戦略

**準備：ConfigMapのバージョン管理**

```bash
# 現在のルールをバックアップ
kubectl get configmap falco-rules -n falco -o yaml > falco-rules-backup-$(date +%Y%m%d).yaml

# 新ルールを適用
kubectl apply -f falco-rules-new.yaml

# 問題が発生したら即座にロールバック
kubectl apply -f falco-rules-backup-20250126.yaml
kubectl rollout restart daemonset/falco -n falco
```

**自動ロールバック条件**：

```yaml
# Prometheus AlertRule例
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: falco-alert-spike
  namespace: falco
spec:
  groups:
  - name: falco
    rules:
    - alert: FalcoAlertSpike
      expr: |
        rate(falco_events{priority="warning"}[5m]) > 100
      for: 10m
      annotations:
        summary: "Falco alert spike detected - possible rule misconfiguration"
        description: "Falco is generating >100 alerts/min for 10 minutes"
        action: "Consider rollback to previous rule version"
```

---

## 7. ルール管理のベストプラクティス

### 7.1 ファイル構成

```
/etc/falco/
├── falco.yaml                    # Falco本体設定
├── falco_rules.yaml              # デフォルトルール（変更不可）
├── rules.d/
│   ├── 00_macros_lists.yaml      # 共通マクロ・リスト
│   ├── 10_production.yaml        # 本番環境用ルール
│   ├── 20_compliance.yaml        # コンプライアンス用
│   ├── 30_custom.yaml            # カスタムルール
│   └── 99_exceptions.yaml        # 例外定義（最後に読み込み）
```

### 7.2 Gitでのバージョン管理

```bash
# ルールリポジトリ構成
falco-rules-repo/
├── .github/
│   └── workflows/
│       └── validate-rules.yaml   # CI/CD
├── environments/
│   ├── production/
│   │   ├── rules.yaml
│   │   └── exceptions.yaml
│   ├── staging/
│   └── development/
├── tests/
│   └── rule_tests.yaml
└── README.md
```

**CI/CD検証パイプライン**：

```yaml
# .github/workflows/validate-rules.yaml
name: Validate Falco Rules
on: [pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Falco
        run: |
          curl -s https://falco.org/repo/falcosecurity-packages.asc | apt-key add -
          echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list
          apt-get update && apt-get install -y falco

      - name: Validate Syntax
        run: |
          falco --validate rules.yaml --dry-run

      - name: Run Rule Tests
        run: |
          ./tests/run_rule_tests.sh
```

### 7.3 ドキュメント化

各ルールに**なぜこのルールが必要か**を記載：

```yaml
- rule: SSH Server Started in Container
  desc: |
    Detect SSH server (sshd) starting in a container.

    **Why**: Containers should be immutable. SSH access suggests:
    - Manual configuration changes (violates GitOps)
    - Potential backdoor installation
    - Lateral movement by attackers

    **Exception**: CI/CD test containers that validate SSH configurations

    **Response**:
    1. Investigate the pod immediately
    2. Check if authorized via JIRA ticket
    3. If unauthorized, terminate pod and alert security team

    **References**:
    - MITRE ATT&CK: T1021.004 (Remote Services: SSH)
    - CIS Kubernetes Benchmark: 5.2.5
  condition: >
    spawned_process and
    container and
    proc.name = "sshd"
  output: >
    SSH server started in container
    (user=%user.name command=%proc.cmdline
     container=%container.name pod=%k8s.pod.name
     namespace=%k8s.ns.name image=%container.image.repository)
  priority: WARNING
  tags: [network, ssh, mitre_t1021_004, cis_5.2.5]
```

---

## 8. まとめ

この章では、実運用に耐えるFalcoルールの書き方を学びました。

### 学んだこと

✅ **スコープ限定** - namespace/labelsで検知対象を絞る
✅ **例外処理** - exception機能で正常動作を除外
✅ **ノイズ削減** - ベースライン収集と段階的適用
✅ **影響範囲テスト** - カナリアデプロイとロールバック戦略
✅ **実運用パターン** - CI/CD、kubectl exec、コンプライアンス対応

### 次のステップ

- **第6回**：Falcosidekickで可視化とアラート通知を実装
- **第7回**：Kubernetes Audit LogとFalcoの連携
- **第8回**：CI/CDパイプラインへの組み込み

### 練習問題

**問題1**：あなたの環境で最もノイジーなルールを特定し、例外を設計してください。

**問題2**：kubectl execを本番環境で検知し、Slackに通知するルールを書いてください。

**問題3**：新しいルールを本番環境に安全に適用する手順書を作成してください。

---

## 参考資料

- [Falco Rules Best Practices](https://falco.org/docs/rules/best-practices/)
- [Exception Handling Guide](https://falco.org/docs/rules/exceptions/)
- [Rule Condition Syntax](https://falco.org/docs/rules/conditions/)
- [Supported Fields Reference](https://falco.org/docs/reference/rules/supported-fields/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
