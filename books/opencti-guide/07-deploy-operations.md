---
title: "第7章: 構築・運用ベストプラクティス — Docker Composeで本番環境を作る"
---

この章では、OpenCTIとOpenAEVをDocker Composeで本番環境にデプロイし、SOCワークフローに組み込むためのベストプラクティスを解説します。

## 7.1 全体アーキテクチャ

```
┌─────────────────────────────────────────────────────┐
│                  OpenCTI Platform                     │
│  ┌─────────────────────────────────────────────┐    │
│  │  Web UI / GraphQL API / REST API            │    │
│  └─────────┬──────────────────────────┬────────┘    │
└────────────┼──────────────────────────┼─────────────┘
             │                          │
    ┌────────┴────────┐    ┌───────────┴──────────┐
    │ OpenCTI Workers │    │ OpenAEV Platform      │
    │ (Connectors)    │    │ (Attack & Validation) │
    └────────┬────────┘    └───────────┬──────────┘
             │                         │
    ┌────────┴────────┬───────────────┴────────┐
    │                  │                        │
┌───┴──────┐  ┌───────┴───────┐  ┌────────────┴──┐
│PostgreSQL│  │Elasticsearch  │  │    Redis       │
│(Storage) │  │(Index/Search) │  │ (Cache/Queue)  │
└──────────┘  └───────────────┘  └───────────────┘
                    │
            ┌───────┴─────────┐
            │  RabbitMQ       │
            │  (Task Queue)   │
            └─────────────────┘
```

### コンポーネント一覧

| コンポーネント | 役割 | 必須性 | リソース目安 |
|---|---|---|---|
| PostgreSQL | 永続データストレージ | 必須 | 4GB RAM, 20GB+ Disk |
| Elasticsearch | フルテキストインデックス | 必須 | 8GB+ RAM, 100GB+ Disk |
| Redis | セッション・キャッシュ | 必須 | 2GB RAM |
| RabbitMQ | 非同期ジョブキュー | 必須 | 2GB RAM |
| MinIO | ドキュメント保存 (S3互換) | 推奨 | 1GB RAM, 50GB+ Disk |
| OpenCTI Platform | Web UI / API | 必須 | 2-4GB RAM |
| OpenCTI Workers | コネクタ実行エンジン | 必須 | 1-2GB RAM/worker |
| OpenAEV Platform | 攻撃シミュレーション | オプション | 2-4GB RAM |

## 7.2 ハードウェア要件

| 環境 | RAM | CPU | ストレージ | 用途 |
|---|---|---|---|---|
| **開発・学習** | 16GB | 4 cores | 100GB SSD | ローカル開発、POC |
| **本番 小規模** | 32GB | 8 cores | 500GB SSD | 組織内用途 |
| **本番 中規模** | 64GB | 16 cores | 1TB SSD | エンタープライズ |

### Linuxカーネルチューニング

```bash
# /etc/sysctl.conf に追加
vm.max_map_count=1048576
vm.swappiness=10
net.core.somaxconn=65535

# 反映
sudo sysctl -p
```

:::message
本番環境では `vm.max_map_count` が最低でも 262144 以上必要です。Elasticsearchが起動しない場合はこのパラメータを確認してください。
:::

## 7.3 OpenCTI のデプロイ

### ステップ1: リポジトリクローンと環境設定

```bash
mkdir -p ~/opencti-deployment && cd ~/opencti-deployment
git clone https://github.com/OpenCTI-Platform/docker.git && cd docker

cat > .env << 'EOF'
OPENCTI_VERSION=6.1.0
OPENCTI_ADMIN_EMAIL=admin@opencti.local
OPENCTI_ADMIN_PASSWORD=ChangeMe123!
OPENCTI_ADMIN_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
OPENCTI_BASE_URL=https://opencti.example.com
POSTGRES_PASSWORD=ChangeMe456!
POSTGRES_USER=opencti
REDIS_PASSWORD=ChangeMe789!
MINIO_ROOT_USER=opencti
MINIO_ROOT_PASSWORD=ChangeMe111!
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=ChangeMe222!
EOF
```

**OPENCTI_ADMIN_TOKEN** は `uuidgen` コマンドで安全なランダムUUIDを生成してください。

### ステップ2: Docker Compose起動

```bash
docker-compose up -d
docker-compose logs -f opencti
curl http://localhost:4000/health
# {"status":"OK"}
```

### ステップ3: 初回ログイン

ブラウザで `http://localhost:4000` にアクセスし、`.env` で設定した管理者アカウントでログインします。初回ログイン後、ユーザー管理、組織設定、デフォルトマーキング、APIトークン生成を行います。

## 7.4 OpenAEV のデプロイ

```bash
mkdir -p ~/openaev-deployment && cd ~/openaev-deployment
git clone https://github.com/OpenBAS-Platform/docker.git && cd docker

cat > .env << 'EOF'
OPENAEV_VERSION=2.0.0
OPENAEV_ADMIN_EMAIL=admin@openaev.local
OPENAEV_ADMIN_PASSWORD=ChangeMe123!
OPENAEV_ADMIN_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
OPENAEV_BASE_URL=https://openaev.example.com
POSTGRES_PASSWORD=ChangeMe456!
REDIS_PASSWORD=ChangeMe789!
EOF

docker-compose up -d
```

## 7.5 OpenCTI ↔ OpenAEV統合デプロイ

両プラットフォームを連携させるには、OpenCTI側に OpenAEV コネクタを追加します。

```yaml
connector-openaev:
  image: opencti/connector-openaev:latest
  environment:
    - OPENCTI_URL=http://opencti:8080
    - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
    - CONNECTOR_ID=${CONNECTOR_OPENAEV_ID}
    - OPENAEV_URL=http://openaev:8080
    - OPENAEV_TOKEN=${OPENAEV_API_TOKEN}
```

## 7.6 運用のポイント

### バックアップ戦略

| データ | バックアップ方法 | 頻度 |
|--------|-------------|------|
| PostgreSQL | `pg_dump` | 日次 |
| Elasticsearch | Snapshot API | 日次 |
| MinIO | `mc mirror` | 日次 |
| 設定ファイル (.env, docker-compose.yml) | Git管理 | 変更時 |

### アップデート手順

```bash
# 1. バックアップ取得
docker-compose exec postgres pg_dump -U opencti opencti > backup.sql

# 2. イメージ更新
# .env の OPENCTI_VERSION を更新
docker-compose pull

# 3. 再起動
docker-compose up -d
```

---

## 7.7 SOCへの組み込み戦略

### フェーズ別アプローチ

**Phase 1: IOC参照フェーズ（導入1-3ヶ月目）** — SOC AnalystがOpenCTI dashboardでIOC検索する運用を開始。SIEM/EDRとの統合は行わず手動参照のみ。

**Phase 2: 自動エンリッチメントフェーズ（導入4-9ヶ月目）** — SIEM・SOARとの連携を開始。アラート発火時にOpenCTIからの脅威コンテキストが自動付加される仕組みを構築。

**Phase 3: 脅威インフォームドディフェンスサイクル（導入10ヶ月以降）** — MITRE ATT&CKとOpenAEVテストを活用した、継続的な防御姿勢改善サイクルを確立。

### チーム構成と役割分担

| 役割 | ツール | 責務 |
|------|--------|------|
| **SOC Analyst** | OpenCTI Dashboard | インシデント調査、IOC参照 |
| **TI Analyst** | OpenCTI Full Platform | 脅威情報の収集・分析 |
| **Security Engineer** | OpenCTI API, pycti | パイプライン構築、自動化 |
| **Red/Purple Team** | OpenAEV Scenarios | シナリオ設計、テスト実行 |

### CTIプログラムの成功メトリクス

- **MTTD**: 導入前の平均48時間 → 目標15分以内
- **誤検知削減率**: 目標30%削減
- **Critical脆弱性修復時間**: 2週間 → 3日以内
- **ATT&CK Coverage**: 毎四半期5-10%向上

## 7.8 SIEM連携

### Splunk Enterprise Security

```
OpenCTI → TAXII 2.1 Endpoint → Splunk ES Threat Intelligence Framework → Correlation Rules
```

```spl
| tstats summariesonly=t count from datamodel=Network_Traffic
    where All_Traffic.dest_ip IN (lookup threat_intel_opencti ip)
    by All_Traffic.src, All_Traffic.dest_ip, All_Traffic.dest_port
| lookup threat_intel_opencti ip as dest_ip
    OUTPUT threat_actor, confidence, campaign
| where confidence >= 75
```

### Elasticsearch/Elastic Security

```python
from pycti import OpenCTIApiClient
from elasticsearch import Elasticsearch

opencti = OpenCTIApiClient(url=OPENCTI_URL, token=OPENCTI_TOKEN)
es = Elasticsearch(hosts=[ES_URL])

indicators = opencti.indicator.list(
    filters={"mode": "and", "filters": [
        {"key": "confidence", "values": ["75"]}
    ]}, first=100
)
for indicator in indicators:
    es.index(index="threat-intel-opencti", body={
        "type": indicator["pattern_type"],
        "value": indicator["pattern"],
        "confidence": indicator["confidence"],
    })
```

:::message
信頼度スコアのフィルタリングは重要です。低信頼度のIOCを大量にSIEMに投入すると、アラート疲れの原因になります。推奨閾値は75以上です。
:::

## 7.9 SOAR連携

### Cortex XSOAR

```
EDR Alert → SOAR Webhook → Query OpenCTI → Enrich Alert → Auto-Escalate if APT
```

### Tines（ノーコードSOAR）

TinesではOpenCTIのGraphQL APIにHTTP Actionを送信し、レスポンスをパースしてワークフローを分岐させます。

## 7.10 EDR/NDR連携

### CrowdStrike Falcon — IOC自動配信

```python
class CrowdStrikeFalconIntegration:
    def sync_iocs(self):
        indicators = self.opencti.indicator.list(
            filters={"key": "confidence", "values": ["80"]},
            first=500
        )
        for indicator in indicators:
            ioc_type, ioc_value = self._parse_stix_pattern(indicator["pattern"])
            self._push_to_falcon(ioc_type, ioc_value, indicator["confidence"])
```

### Suricata IOCルール自動生成

```python
def generate_suricata_rules(indicators):
    rules = []
    for ind in indicators:
        ioc_type, value = parse_stix_pattern(ind["pattern"])
        if ioc_type == "domain-name":
            rules.append(
                f'alert dns any any -> any any '
                f'(msg:"OpenCTI IOC: {value}"; '
                f'dns.query; content:"{value}"; nocase; '
                f'sid:{ind["x_opencti_id"][:8]}; rev:1;)'
            )
    return "\n".join(rules)
```

:::message
EDR/NDRへの自動IOC配信では、信頼度90以上はブロック、80以上はアラート、それ未満は監視のみ、というポリシーが推奨されます。
:::

## 7.11 脆弱性優先度付け

CVSSスコアだけでは不十分です。OpenCTI + CISA KEV + OpenAEVを組み合わせた脅威インフォームド優先度付けを構築します。

| CVSS | 攻撃実績 | 防御状況 | 優先度 | SLA |
|------|---------|---------|--------|-----|
| High/Critical | ✓ (CISA KEV) | ✗ (OpenAEV) | **CRITICAL** | 3日 |
| High | ✓ | ✓ | HIGH | 1週間 |
| High | ✗ | ✗ | MEDIUM | 2週間 |
| Medium | ✓ | ✗ | HIGH | 1週間 |

## 7.12 IOC自動配信パイプライン

### IOCライフサイクル管理

| IOCタイプ | 推奨有効期間 | 理由 |
|----------|------------|------|
| IP Address | 30日 | 攻撃者はIPを頻繁に変更 |
| Domain | 90日 | ドメインは比較的安定 |
| File Hash (SHA256) | 180日 | マルウェアの亜種がリリースされるまで |
| URL | 14日 | URLは使い捨てが多い |

```
OpenCTI (Source of Truth)
    ↓
IOC Export (フィルタ: 信頼度 ≥ 75)
    ↓
┌───────────┬────────────┬──────────────┐
│ SIEM Feed │ EDR Feed   │ Firewall Feed│
│ (All IOC) │ (Hash, IP) │ (IP, Domain) │
└───────────┴────────────┴──────────────┘
```

## 7.13 OpenAEVテスト自動化

```yaml
# Kubernetes CronJob
apiVersion: batch/v1
kind: CronJob
metadata:
  name: openaev-weekly-test
spec:
  schedule: "0 2 * * 0"  # 毎週日曜 AM2:00
  jobTemplate:
    spec:
      containers:
        - name: openaev-runner
          image: openaev/cli:latest
          command: ["openaev", "run", "--scenario", "weekly-defense-validation"]
```

テスト結果をOpenCTIにフィードバックし、脅威アクターごとの防御カバレッジを可視化します。

## 7.14 レポーティングとダッシュボード

### 週次CTIレポート自動生成

OpenCTI APIで週次の脅威インテリジェンスサマリーを自動生成し、メールやSlackで配信します。

### OpenCTI カスタムダッシュボード

- **New Indicators Last 7 Days**: IOC追加の傾向
- **Top Threat Actors**: 最も活動的な脅威アクター
- **High-Confidence IOCs**: 信頼度90%以上のIOC数
- **Vulnerable Infrastructure**: OpenAEVテスト結果に基づいた脆弱性ランキング

### Grafana統合

Prometheus exporterを実装し、OpenCTIのメトリクス（インジケータ数、高信頼度IOC数、マルウェア数など）を定期収集。Grafanaダッシュボードで可視化し、セキュリティ経営層に脅威インテリジェンスプログラムの効果を説明できます。
