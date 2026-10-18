---
title: "第10章：Falco・eBPFによる攻撃の追跡"
---

# 第10章：Falco・eBPFによる攻撃の追跡

## この章で学ぶこと

- 研究B：syscallだけで攻撃経路を最初から最後まで追跡できるのか
- Kubernetes Audit Logsとの突合で何が埋まり、何が埋まらないか
- 研究A：Lab 1〜17の実機検証結果を集計した検知カバレッジ
- 未検知だったケースの原因分類（本文執筆時の想定より多様だった）

第4章から第9章まで、8フェーズ・17本の実験を個別に見てきました。本章ではそれらを横断し、**「ひとつの攻撃チェーン全体」をsyscallだけで追えるのか**という問いに正面から取り組みます。Lab 18〜20は新しい攻撃ではなく、**Lab 1〜17で実際に収集した実ログを使った再分析**です。

---

## 研究B：Syscallだけで攻撃経路を追跡できるのか

### Lab 18: Falcoログのみでの再構築を試みる

`vulnerable-webapp`（container_id=`115c63fa4162`）に対して行った一連の操作——第4章のコマンドインジェクション→第5章のリバースシェル→第9章のメタデータAPI接続——のFalcoログだけを時系列に並べます。

```
[Lab1] 11:03:09 Critical Shell spawned without a tty (container_id=115c63fa4162)
[Lab5] 11:12:23 Notice  Redirect stdout/stdin to network connection (container_id=115c63fa4162)
[Lab16]12:00:06 Critical Contact cloud metadata service from container (container_id=115c63fa4162)
```

**`container_id`が共通しているため、この3つが「同一コンテナでの一連の行動」であることはFalcoログだけでも追跡できました。** これはLab 1〜17を通して、攻撃対象のコンテナを使い回していたために成立した相関で、**同一コンテナ内で完結する攻撃チェーンであればFalcoログ単体でもcontainer_idを軸に再構築できる**ことを示しています。

一方、第6章のLab 8（`over-privileged-sa-pod`、container_id=`2f472e138129`）は**別のコンテナ**で実行しており、Falcoのcontainer_idだけでは、Lab 1→5→16の流れと**繋がりません**。

### Lab 19: Kubernetes Audit Logsとの突合

Lab 8の「ServiceAccountトークン奪取→Secret一覧取得」は、`system:serviceaccount:lab:deploy-bot`というユーザー名でAudit Logsに記録されています。

```json
{"verb": "list", "user": {"username": "system:serviceaccount:lab:deploy-bot", ...,
  "extra": {"authentication.kubernetes.io/pod-name": ["over-privileged-sa-pod"]}},
 "objectRef": {"resource": "secrets", "namespace": "kube-system"}}
```

ここで相関キーが**container_idからserviceaccount名（`deploy-bot`）に切り替わります**。第8章Lab 15（ノード間移動）のexec操作も同じ`deploy-bot`のトークンで行われているため、Audit Logsの`user.username`を軸にすれば、**Lab 4（漏洩）→Lab 8（API悪用）→Lab 15（ノード間移動）**の3本を1本の線としてつなげられます。

**しかし、Falcoのcontainer_id系列（Lab1→5→16）とAudit Logsのserviceaccount系列（Lab4→8→15）は、互いに独立した2本の線のままで、これだけでは交わりません。**

### Lab 20: 相関キーを変えながら全体をつなぐ

実際には、2つの系列は「攻撃者が同一人物である」という前提以外に、ログ上の直接的な結合キーを持ちません。本ラボ規模では両系列をまたぐ明示的な操作（例：Lab 1の侵入先からLab 8のSAトークンを盗む、という具体的な一手）を行っていないため、**この2系列を1本につなぐログ上の証拠は存在しませんでした**。

![図10-1：4つのデータソースを横断した攻撃チェーンの相関再構築](/images/fig-ch10-correlation-timeline.png)

図に示した4データソースの統合は概念図であり、本ラボで実機検証できたのは**Falco**と**Kubernetes Audit Logs**の2つのみです。本書が挙げた残り2つのデータソースは、今回の検証範囲では確認できませんでした。

- **ネットワーク観測（CNI flow log）**: kindクラスタはkindnet CNI（Calicoではない）のため未検証（第8章の注記を参照）
- **クラウドAudit Trail（CloudTrail等）**: ローカルkindラボには実クラウドが存在しないため検証不可（第9章の注記を参照）

**研究Bの結論（訂正版）**: 当初の結論「syscallだけでは攻撃チェーン全体を追跡できない」自体は実機でも支持されますが、**理由の説明が変わります**。本文は「データソースが足りないから繋がらない」という説明でしたが、実際には**「データソースを足しても、相関キーが境界ごとに変わるため、自動的には繋がらない」**という、より深い問題であることが分かりました。

> **相関のための「キー」は固定ではなく、攻撃がどの境界を越えるかによって変わる**（同一コンテナ内＝container_id、認証情報の窃取と再利用＝identity、ネットワーク越しの移動＝送信元/宛先IP）。**キーが変わる境界をまたぐ瞬間、それまでの文脈は失われ、分析者が手動で「同一攻撃者による一連の行動」と仮定して繋ぎ直す必要があります。**

4本すべてのデータソースを使った完全な実証は、実クラウド環境・Calico等の高機能CNIを使う発展的な検証として今後の課題とします。

---

## 研究A：検知カバレッジの実機集計

Lab 1〜17の実機結果に基づく、最終的な検知カバレッジです。本文執筆時の想定（架空のルール名を多く含んでいました）ではなく、すべて実機で確認した結果のみを集計しています。

| Lab | フェーズ | 攻撃は成立したか | 標準ルールで検知 | カスタムルールで検知 |
|---|---|---|---|---|
| 1 | Initial Access | ✅ | ❌ | ✅（2回の失敗を経て） |
| 2 | Initial Access | ✅ | ❌ | ✅（1回目は失敗） |
| 3 | Initial Access | ❌（現代のデフォルトで対策済み） | N/A | N/A |
| 4 | Initial Access | ✅ | ✅（Audit Logs） | - |
| 5 | Execution | ✅ | ✅ | - |
| 6 | Execution | ✅ | ❌ | ✅ |
| 7 | Privilege Escalation | ✅ | ✅（部分） | ✅（補強） |
| 8 | Privilege Escalation | ✅ | ✅（部分）＋Audit Logs | - |
| 9 | Privilege Escalation | ✅ | ✅ | - |
| 10 | Container Escape | ✅ | ❌ | ✅（2回目で成功） |
| 11 | Container Escape | △（要追加権限） | ❌ | ✅（ノイズ対策後） |
| 12 | Container Escape | ✅ | ❌ | ✅（一発成功） |
| 13 | Lateral Movement | ✅ | ❌ | ❌（未実装） |
| 14 | Lateral Movement | ✅ | ❌ | ✅（ルール再設計後） |
| 15 | Lateral Movement | ✅ | - | ✅ Audit Logsのみ |
| 16 | Credential Access | ✅（接続試行まで） | ❌ | ✅ |
| 17a（S3） | Exfiltration | ❌（認証情報なし） | ❌ | △（副次的） |
| 17b（DNS） | Exfiltration | ✅ | ❌ | ❌（原理的に不可能） |

### 集計

攻撃が成立した15シナリオのうち：

- **標準ルールのみで検知できたのは5本**（Lab 4, 5, 7, 8, 9 ＝ 33%）
- **カスタムルールを追加して検知できたのは7本**（Lab 1, 2, 6, 10, 11, 12, 14, 16）
- **原理的に検知不可能、またはFalcoの設計外と判明したのは2本**（Lab 13のスキャン検知、Lab 17bのDNS exfiltration）
- **攻撃自体が現在のデフォルト設定では成立しなかったのは1本**（Lab 3）

本文執筆時の想定（標準ルール40%、カスタムルール込み70%）という数値は架空のものであり、実機検証の結果に基づいて全面的に置き換えました。

## 未検知の原因分析

未検知・低精度だったケースを、原因別に分類し直します。本文執筆時の想定より、**原因の種類がずっと多様で深刻**でした。

| 原因 | 該当Lab | 対策の方向性 |
|---|---|---|
| ルールの条件設計そのものの誤り（`proc.tty`依存、`outbound`マクロの前提） | Lab 1, 2 | マクロの実装を確認した上でカスタムルールを書く |
| ルールの再現性の無さ（`proc.pname`解決のタイミング依存） | Lab 1→14 | 環境依存の情報に頼らない、最もシンプルな条件に倒す |
| Falcoのアーキテクチャ上そもそも不可能（パケット内容・頻度分析） | Lab 13, 17b | ネットワーク観測・DNSサーバログ等、別データソースが必須 |
| 攻撃自体が現代の環境では成立しない | Lab 3 | 検知ではなく、デフォルト設定の進化そのものが対策になっている |
| 検証環境の制約（実クラウド・高機能CNIが無い） | Lab 16, 17a | 発展的な検証課題として切り出す |
| カスタムルール自身が自己ノイズを誤検知 | Lab 11 | Falco自身の動作を除外する条件を加える |

**この分類が示すのは、「ルールを足せば足すほど検知率が上がる」という単純な話ではない**ということです。原因によって対策の筋が全く異なり、**どの原因に当てはまるかを見極めずにルールを書き足すと、Lab 1・11のように何度も失敗を繰り返すことになります**。

次章では、ここまで「検知できるか／できないか」という二択で見てきた視点を離れ、**検知の精度と、監視の負荷・遅延・リソース消費のトレードオフ**（研究C）を扱います。

## 参考資料

- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Falco Default Rules（falcosecurity/rules）](https://github.com/falcosecurity/rules)
- [Kubernetes Audit Logging（公式ドキュメント）](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [k8s-attack-runtime-security-lab（本書の実験コード一式、全Labの実測ログを含む）](https://github.com/keitahigaki-prog/k8s-attack-runtime-security-lab)
