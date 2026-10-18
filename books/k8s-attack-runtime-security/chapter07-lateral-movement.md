---
title: "第7章：Lateral Movement - クラスタ内横展開"
---

# 第7章：Lateral Movement - クラスタ内横展開

## この章で学ぶこと

- 単一のPodを侵害した後、攻撃者がクラスタ内でどう横展開するか
- Lab 13〜15の実験手順とFalco・ネットワーク観測それぞれの結果
- 「ノード内の検知」だけでは追えない、複数ノードをまたぐ攻撃の見え方

本章ではMITRE ATT&CK for Containersの**Lateral Movement**戦術を扱います。第2章で準備したネットワーク観測（CNIフローログ／tcpdump）が初めて主役になる章です。

---

## Lab 13: クラスタ内ネットワークスキャン

- **MITRE ATT&CK for Containers**: T1046 (Network Service Discovery)
- **前提**: 侵害済みPodから、同一クラスタ内の他Podへスキャンを実行

```bash
# 侵害済みPod内で
nmap -sT 10.0.0.0/16 -p 1-1024
```

**Falcoの検知結果**:

```
19:15:02.220134000: Notice Multiple Outbound Connections (container=victim-pod count=847 window=10s)
```

標準ルールの中には、短時間に大量の送信接続を行うプロセスに反応するものがあり、これがスキャンの兆候を捉えています。ただし、**「ポートスキャンである」という確信までは持てず、あくまで「異常な接続数」という粒度の検知**です。

**ネットワーク観測（CNIフローログ）の記録**:

```
10.0.3.12 -> 10.0.5.0/24 (ports 1-1024, 847 flows, 10s window) DENIED_BY_NONE
```

CNIのフローログでは、**宛先の分布（連続するIPレンジへの接続）とポート分布（広い範囲へのTCP SYN）**から、より高い確度でポートスキャンと判断できます。

**考察**: Falcoは「このコンテナから大量の接続が出ている」ことは分かりますが、**「どこへ」「どういうパターンで」接続しているか**はネットワーク観測の方が得意です。この章で初めて、syscallベースの検知とネットワークベースの検知の相互補完が明確に機能しました。

## Lab 14: 他Podへの侵入・Pod間移動

- **MITRE ATT&CK for Containers**: T1021 (Remote Services の発展形)
- **前提**: Lab 13のスキャンで発見した、認証の緩いデバッグ用サービス（例：認証なしのJupyter Notebook）が動く別Podへ接続

```bash
curl http://10.0.5.42:8888/api/kernels -X POST
```

**Falcoの検知結果**: 対象外（発信元Podから見ると、単なる外向きHTTP接続であり、それ自体は異常なプロセス実行ではない）

**侵害された側（10.0.5.42）でのFalco検知結果**:

```
19:20:44.010022000: Warning Unexpected outbound connection source (container=jupyter-debug-pod source=10.0.3.12 unexpected_source=true)
```

**考察**: Lateral Movementの検知で重要なのは、**「発信元」ではなく「着地点」のPodで何が起きたかを見る**ことです。本書のラボでは全Podに同じFalco DaemonSetが入っているため、**どちらの視点からも観測でき、両方を突き合わせることで「どのPodからどのPodへ移動したか」のチェーンが再構築できます**。単一Podのログだけ見ていると、この移動の全体像は見えません。

## Lab 15: ノード間移動（SSH/APIサーバ悪用）

- **MITRE ATT&CK for Containers**: T1021.004 (SSH), T1550 (Use Alternate Authentication Material)
- **前提**: Lab 14で侵害したPodから、そのPodが稼働するノードとは別のノードへ、kubeletの認証情報を使ってkubectl exec相当の操作を行う

```bash
# 盗んだService Account Tokenで、別ノード上のPodにexec
kubectl --token=$STOLEN_TOKEN exec -it other-node-pod -- sh
```

**Falcoの検知結果（移動先ノードのPod内）**:

```
19:28:09.330112000: Notice Unexpected Interactive Shell Session (container=other-node-pod user=unknown source=kube-apiserver)
```

**Audit Logsの記録**:

```json
{
  "verb": "create",
  "objectRef": {"resource": "pods", "subresource": "exec", "name": "other-node-pod"},
  "user": {"username": "system:serviceaccount:lab:over-privileged-sa"},
  "sourceIPs": ["10.0.3.12"]
}
```

**考察**: `kubectl exec`によるノードをまたいだ移動は、**Audit Logsで「誰が」「どのPodに対して」execしたかが明確に残ります**。一方Falcoは「execされた結果、Pod内で何が起きたか」を見ます。ノード間移動そのものはAPIサーバを経由するため、**この章で最もAudit Logsの重要性が際立つ実験**でした。

---

## 本章のまとめ

| Lab | 手法 | Falco | ネットワーク観測 / Audit Logs | ポイント |
|---|---|---|---|---|
| 13 | クラスタ内スキャン | △ 異常接続数のみ検知 | ✅ 宛先・ポート分布から高確度で判定 | 相互補完が機能する典型例 |
| 14 | Pod間移動 | ✅ 着地点Podで検知 | - | 発信元ではなく着地点を見る |
| 15 | ノード間移動（exec悪用） | △ Pod内の挙動のみ | ✅ Audit Logsでexec操作を記録 | APIサーバ経由の移動はAudit Logs必須 |

横展開のフェーズでは、**単一のデータソースだけで攻撃チェーン全体を追うことはできない**ことがはっきりしました。次章では、横展開の先で何が狙われるのか——Credential AccessとExfiltrationを扱います。
