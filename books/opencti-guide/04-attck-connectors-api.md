---
title: "第4章: ATT&CK・コネクタ・API — OpenCTIを使いこなす"
---

## 4.1 MITRE ATT&CKとは

MITRE ATT&CKは、実際に観測されたサイバー攻撃の手法（TTP）を体系的にカタログ化したフレームワークです。世界中のセキュリティコミュニティで事実上の標準として使われています。

ATT&CKは大きく以下の構造になっています。

```
Tactics（戦術）     → 攻撃者の目的（例: Initial Access, Persistence）
  └── Techniques（技術） → 目的を達成する方法（例: Phishing, Boot or Logon Autostart）
        └── Sub-techniques → より具体的な手法（例: Spearphishing Attachment）
```

## 4.2 OpenCTIでのATT&CK Attack Patterns

> **確認方法**: https://demo.opencti.io/dashboard/techniques/attack_patterns

<!-- スクリーンショット: Attack Patterns -->

デモ環境には2,310件以上のAttack Patternが登録されています。リスト表示では以下が確認できます。

- **Kill chain phase**: ATT&CKの戦術フェーズ（credential-access、defense-evasion、collectionなど）
- **ID**: MITRE ATT&CKのID（T1003.008、T1453、T1548など）
- **Name**: 技術名（/etc/passwd and /etc/shadow、Abuse Accessibility Features、Access Token Manipulationなど）
- **Original creation date / Modification date**

## 4.3 ATT&CKの活用方法

**脅威アクターのプロファイリング**: 特定のIntrusion Setの詳細ページから「ATT&CK」タブを見ると、そのグループが使用する攻撃手法がATT&CKマトリクス上にマッピングされます。これにより、そのグループに対してどの防御策を優先すべきかが明確になります。

**防御カバレッジの評価**: 自組織のセキュリティ対策がATT&CKのどのテクニックをカバーしているかを照らし合わせることで、防御の「穴」を見つけることができます。

**レポートの文脈理解**: 脅威レポートにATT&CKのIDが記載されている場合、そのIDをOpenCTIで検索することで、同じ手法を使う他の脅威アクターや関連するIOCを芋づる式に辿ることができます。

## 4.4 Kill Chain Phase（キルチェーンフェーズ）

ATT&CKのTacticsは攻撃の各段階に対応しています。OpenCTIでは「Kill chain phase」として表示されます。

| Phase | 日本語 | 説明 |
|-------|--------|------|
| Reconnaissance | 偵察 | 標的の情報を収集 |
| Resource Development | リソース開発 | 攻撃インフラの準備 |
| Initial Access | 初期アクセス | 標的ネットワークへの侵入 |
| Execution | 実行 | 悪意のあるコードの実行 |
| Persistence | 永続化 | アクセスの維持 |
| Privilege Escalation | 権限昇格 | より高い権限の取得 |
| Defense Evasion | 防御回避 | 検知の回避 |
| Credential Access | 認証情報アクセス | パスワード等の窃取 |
| Discovery | 探索 | 内部ネットワークの調査 |
| Lateral Movement | 横展開 | 他のシステムへの移動 |
| Collection | 収集 | 目的のデータを集める |
| Command and Control | C2通信 | 外部との通信維持 |
| Exfiltration | 持ち出し | データの外部送信 |
| Impact | 影響 | システムの破壊・暗号化 |

---

## 4.5 コネクタとは

コネクタはOpenCTIの心臓部と言っても過言ではありません。外部のデータソースから脅威情報を自動的に取り込み、プラットフォームを常に最新の状態に保つ仕組みです。

> **確認方法**: https://demo.opencti.io/dashboard/data/ingestion/connectors

<!-- スクリーンショット: Connectors -->

## 4.6 コネクタの種類

コネクタは4つのタイプに分類されます。

| タイプ | 説明 | 例 |
|--------|------|----|
| **External import** | 外部ソースからデータを取り込む | Abuse.ch URLhaus、AlienVault、CISA KEV、CVE (NVD) |
| **Internal import** | アップロードされたファイルからデータを抽出 | ImportFileStix（STIX JSONの読み込み）、ImportDocument（PDFからの抽出） |
| **Internal enrichment** | 既存データに追加情報を付与 | AbuseIPDB（IPアドレスの評判情報）、VirusTotal |
| **Internal export** | データを外部フォーマットでエクスポート | ExportFileStix2、ExportFileCsv、ExportFileTxt |

## 4.7 デモ環境のコネクタ一覧

デモ環境のMonitoring画面（Data > Ingestion > Monitoring）では、登録されたコネクタの一覧と動作状況が確認できます。

画面上部のステータスカードが示す情報は以下の通りです。

| 項目 | 説明 | デモ環境の値 |
|------|------|-------------|
| Connected workers | 稼働中のワーカー数 | 4 |
| Queued bundles | 処理待ちのデータバンドル数 | 0 |
| Bundles processed | 処理済みバンドル/秒 | 0/s |
| Read operations | 読み取り操作/秒 | 11.6/s |
| Write operations | 書き込み操作/秒 | 1/s |
| Total number of documents | 総ドキュメント数 | 60.19M |

## 4.8 主要なコネクタの紹介

デモ環境で動作している主なコネクタを紹介します。

**Abuse.ch URLhaus**: マルウェア配布に使われるURLのフィード。IoTマルウェア（Mirai、Mozi）やフィッシングURLなどが大量に含まれます。

**AlienVault**: AT&T Cybersecurityが運営するOTX（Open Threat Exchange）からの脅威データ。

**CISA Known Exploited Vulnerabilities**: 米国CISAが公開する「実際に悪用が確認された脆弱性」のリスト。パッチ優先度の判断に極めて有用です。

**Common Vulnerabilities and Exposures（CVE）**: NVD（National Vulnerability Database）からのCVE情報。

**DISARM Framework**: 偽情報（Disinformation）の手法を体系化したフレームワーク。

**MITRE ATT&CK**: 前節で紹介したATT&CKフレームワークのデータ。

## 4.9 コネクタの追加方法（セルフホスト環境向け）

デモ環境ではコネクタの追加はできませんが、セルフホスト環境では`docker-compose.yml`にコネクタの設定を追加してデプロイします。

```yaml
# docker-compose.yml に追加する例（VirusTotalコネクタ）
connector-virustotal:
  image: opencti/connector-virustotal:latest
  environment:
    - OPENCTI_URL=http://opencti:8080
    - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
    - CONNECTOR_ID=<新しいUUIDv4>
    - CONNECTOR_NAME=VirusTotal
    - VIRUSTOTAL_TOKEN=<あなたのAPIキー>
  restart: always
  depends_on:
    opencti:
      condition: service_healthy
```

## 4.10 その他のデータ取り込み方法

コネクタ以外にも、以下の方法でデータを取り込めます。

**TAXII Feeds**: STIX/TAXIIプロトコルに対応したフィードを直接購読。

**RSS Feeds**: セキュリティベンダーのブログやレポートをRSSで取り込み、自動的にレポートとして登録。

**CSV Feeds**: CSV形式のIOCリストを取り込み。

**手動インポート**: STIX 2.1 JSONファイルやPDFレポートを直接アップロード。

---

## 4.11 GraphQL API

OpenCTIはGraphQL APIを公開しており、すべての操作をプログラムから実行できます。

APIエンドポイント: `https://<your-opencti>/graphql`

認証にはAPIトークンを使用します。デモ環境でのトークンはProfile画面（右上のアバター > Profile）から確認できます。

## 4.12 APIの基本的な使い方

**Indicatorの検索例（curl）**:

```bash
curl -X POST https://demo.opencti.io/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <YOUR_API_TOKEN>" \
  -d '{
    "query": "{ indicators(first: 5, orderBy: created_at, orderMode: desc) { edges { node { name pattern created } } } }"
  }'
```

**Pythonクライアント（pycti）**:

OpenCTIはPython SDKも提供しています。

```python
from pycti import OpenCTIApiClient

# クライアント初期化
api = OpenCTIApiClient(
    url="https://demo.opencti.io",
    token="<YOUR_API_TOKEN>"
)

# 最新のIndicatorを5件取得
indicators = api.indicator.list(
    first=5,
    orderBy="created_at",
    orderMode="desc"
)

for ind in indicators:
    print(f"{ind['name']} - {ind['pattern']}")
```

## 4.13 他ツールとの連携パターン

OpenCTIは様々なセキュリティツールと連携できます。代表的なパターンを紹介します。

**SIEM連携（Splunk, Elastic Security）**: OpenCTIからIOCをエクスポートし、SIEMのルールに自動連携。不審な通信の検知に活用。

**SOAR連携（Cortex XSOAR, Tines）**: インシデント発生時にOpenCTIのAPIを叩いて関連する脅威情報を自動取得し、調査ワークフローを加速。

**MISP連携**: MISPからのイベント取り込みと、OpenCTIからMISPへのデータ共有の双方向連携が可能。

**Sysdig連携**: Sysdigが検知したランタイム脅威のIOC（不審なIPアドレス、ファイルハッシュなど）をOpenCTIのAPIで照合し、既知の脅威アクターとの関連性を自動チェック。コンテナセキュリティとCTIを橋渡しするユースケースです。

## 4.14 STIX/TAXIIによるデータ共有

OpenCTIはTAXII 2.1サーバーとしても機能します。つまり、他の組織やツールがTAXIIプロトコルでOpenCTIのデータを購読（Subscribe）できます。

```
# TAXIIエンドポイント
https://<your-opencti>/taxii2/

# Discovery
GET /taxii2/
Authorization: Bearer <token>

# API Root
GET /taxii2/root/
Authorization: Bearer <token>
```

## 4.15 自動化のアイデア

APIを活用した自動化の例をいくつか紹介します。

**日次IOCレポートの自動生成**: 毎日新しく追加されたIOCをAPIで取得し、Slackやメールでチームに配信。

**脆弱性の優先度付け**: CVEの情報をOpenCTIから取得し、「実際に攻撃に使われているか」をCISA KEVのデータと照合。CVSSスコアだけでなく、実際の脅威レベルに基づいたパッチ優先度を算出。

**インシデント調査の自動化**: EDRが検知したハッシュ値をOpenCTIで自動照合し、関連するThreat Actor、Campaign、TTPを即座に特定。初動対応の時間を大幅短縮。

次の章では、CTIで「知った」脅威を実際にテストして防御を検証する **OpenAEV** を紹介します。
