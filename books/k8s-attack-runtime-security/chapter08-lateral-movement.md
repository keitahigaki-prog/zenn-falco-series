---
title: "第8章：Lateral Movement - クラスタ内横展開"
---

# 第8章：Lateral Movement - クラスタ内横展開

## この章で学ぶこと

- 単一のPodを侵害した後、攻撃者がクラスタ内でどう横展開するか
- Lab 13〜15の実験手順とFalco・ネットワーク観測それぞれの結果（実機検証）
- 「ノード内の検知」だけでは追えない、複数ノードをまたぐ攻撃の見え方

本章ではMITRE ATT&CK for Containersの**Lateral Movement**戦術を扱います。第3章で触れたとおり、本ラボはkindnet CNIを使用しておりCalicoのフローログは未検証です。

---

## Lab 13: クラスタ内ネットワークスキャン

- **MITRE ATT&CK for Containers**: T1046 (Network Service Discovery)
- **前提**: `vulnerable-webapp`から、worker2上の複数Podに対してポートスキャンを実行

```python
import socket
targets = ['10.244.1.11','10.244.1.4','10.244.1.23','10.244.1.24']
ports = [22,80,443,4444,8080,8888]
for ip in targets:
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((ip, port)); print(f'{ip}:{port} open')
        except Exception: pass
```

**結果**: 攻撃者リスナー・C2サーバ・デバッグサービスの3つの「背後のサービス」を発見できた。

### 実機検証で判明した重大な誤り：標準ルールは一切発火しない

当初「標準ルールの中には、短時間に大量の送信接続を行うプロセスに反応するものがある」と書いていたが、**この想定は誤りだった**。`falco_rules.yaml`で接続数・頻度に関連するルール名を検索したが、該当するものは存在せず（`Redirect STDOUT/STDIN to Network Connection in Container`と`Disallowed SSH Connection Non Standard Port`のみがヒットしたが無関係）、**24回のスキャン接続（成功3回）に対して何も検知されなかった**。

**考察**: これはむしろ**本書の核心的な主張（「syscallベースの検知とネットワークベースの検知は相互補完が必要」）を一段と強く裏付ける結果**になった。Falco単体では「検知の粒度が粗い」のではなく**「そもそも接続頻度ベースの検知ロジックが存在しない」**。CNI flow log（本ラボでは未検証）かtcpdumpによる観測が実質的に必須という結論に強化する。

## Lab 14: 他Podへの侵入・Pod間移動

- **MITRE ATT&CK for Containers**: T1021
- **前提**: Lab 13で発見した`debug-service`（認証なしでコマンドを実行できる模擬デバッグサービス、worker2上）に接続

```python
import urllib.request
req = urllib.request.Request('http://10.244.1.24:8888/', data=b'id; hostname', method='POST')
print(urllib.request.urlopen(req, timeout=5).read().decode())
```

**結果**: 攻撃は成立し、着地点のPod名が返ってきた。

### 実機検証で判明した最重要の発見：第4章のカスタムルールが別のコンテナでは発火しなかった

最初の実行では**何の検知もされなかった**。原因は、第4章で修正したはずの`Shell Spawned Without TTY`ルール（`container_entrypoint`マクロに依存する実装）が、**`debug-service`コンテナでは`proc.pname`が`python3`として正しく解決されていた**ため、`container_entrypoint`（「親プロセス情報が無いか、ランタイムシムであること」を要求するマクロ）の条件を満たさず、ルール全体が不発火になっていたこと。

第4章の`vulnerable-webapp`コンテナでは`proc.pname`が偶然`<NA>`（未解決）だったため`container_entrypoint`を満たしていたが、**これはFalcoのプロセスキャッシュの状態に依存する、再現性のない偶然の一致だった**ことが今回判明した。`container_entrypoint`条件を削除し、親プロセス名の解決状況に依存しない形に修正：

```yaml
condition: >
  spawned_process and container and shell_procs and proc.tty=0
```

修正後は両方のコンテナで正しく発火することを確認：

```
Critical Shell spawned without a tty (... container=app pod=debug-service-... ns=lab ...)
```

トレードオフとして、対話シェルを伴わない正当な自動化スクリプトも拾ってしまう可能性があり、再現率（recall）を上げる代わりに適合率（precision）が下がる。

**考察**: 第4〜7章で使ってきたカスタムルールの説明は、この最終修正版に差し替える必要がある。**「Falcoのプロセスキャッシュの解決状況は環境依存で、それに依存したルールには再現性が無い」**という教訓は、第10章（研究A）で一般化して扱う重要な論点になった。

## Lab 15: ノード間移動（盗んだトークンでのexec悪用）

- **MITRE ATT&CK for Containers**: T1021.004, T1550
- **前提**: 第4章の`deploy-bot`トークンに、`pods/exec`権限を追加（過剰権限なCIトークンという想定を維持するための調整）

### 前提の訂正：最初はpods/exec権限が無く失敗

`deploy-bot`は元々`secrets`のget/listのみで、`pods/exec`権限が無かった。最初の試行は**403 Forbiddenで失敗し、これ自体が「最小権限で運用していれば、この横展開は最初から成立しない」という実証結果**になった。本Labの前提を満たすため、ClusterRoleに`pods/exec`を追加して再実行：

```bash
TOKEN=$(kubectl create token deploy-bot -n lab --duration=1h)
kubectl --server="$APISERVER" --token="$TOKEN" --insecure-skip-tls-verify=true \
  -n lab exec debug-service-76dcf69b7b-d87hq -c app -- id
```

**結果**: 攻撃は成立し、別ノード（worker2）上のPodに対してexecできた。

### Audit Logsの記録：本文の想定どおり（数少ない一致ケース）

```json
{"verb": "create", "user": {"username": "system:serviceaccount:lab:deploy-bot", ...},
 "objectRef": {"resource": "pods", "namespace": "lab", "name": "debug-service-...", "subresource": "exec"},
 "sourceIPs": ["172.19.0.1"]}
```

`pods/exec`というsubresourceへの`create`リクエストとして、誰が・どのPodに対してexecしたかが正確に記録されている。`id`コマンドの実行自体はFalco側でも観測できるが、**それが「正規のkubectl execで入ったのか」「攻撃者が盗んだトークンでexecしたのか」を区別する情報はFalco側には無く**、Audit LogsのsourceIPsとuser情報との突合が必須。

**考察**: 本Labは**実機結果が当初の想定と一致した数少ないケース**。「ノード間移動はAudit Logsが主役」という結論はそのまま維持できる。追加の学びとして、**最小権限運用（`pods/exec`を与えない）そのものが、この攻撃を根本から防ぐ**という点を加える。

---

## 本章のまとめ

| Lab | 手法 | 標準ルールで検知 | カスタムルール/Audit Logs | ポイント |
|---|---|---|---|---|
| 13 | クラスタ内スキャン | ❌（想定と異なり皆無） | ❌（未実装、頻度検知はFalcoの設計外） | 相互補完の必要性をむしろ強く裏付け |
| 14 | Pod間移動 | ❌ | ✅（ルールの再現性問題を発見・修正） | container_entrypointへの依存は危険 |
| 15 | ノード間移動（exec悪用） | - | ✅ Audit Logs（本文想定と一致） | 最小権限運用で攻撃自体を防げる |

横展開のフェーズでは、**単一のデータソースだけで攻撃チェーン全体を追うことはできない**ことがはっきりしました。加えて、**これまで使ってきたカスタムルールの脆さそのものが明らかになった**章でもありました。次章では、横展開の先で何が狙われるのか——Credential AccessとExfiltrationを扱います。

## 参考資料

- [MITRE ATT&CK T1046: Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK T1021: Remote Services](https://attack.mitre.org/techniques/T1021/)
- [Calico Flow Logs（公式ドキュメント）](https://docs.tigera.io/calico/latest/visibility/elastic/flow)
- [kubectl exec（公式ドキュメント）](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#exec)
- [k8s-attack-runtime-security-lab（本書の実験コード一式）](https://github.com/keitahigaki-prog/k8s-attack-runtime-security-lab)
