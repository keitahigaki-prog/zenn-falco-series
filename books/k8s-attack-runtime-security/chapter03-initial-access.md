---
title: "第3章：Initial Access - コンテナへの侵入"
---

# 第3章：Initial Access - コンテナへの侵入

## この章で学ぶこと

- 攻撃者がKubernetesクラスタへの最初の足がかりを得る4つの代表的な経路
- Lab 1〜4の実験手順とFalco／Audit Logsでの観測結果
- 初期侵入の段階でどこまで検知できて、どこが観測の空白になるか

本章から、第2章で構築したラボを使って実際に攻撃チェーンを再現していきます。扱うのはMITRE ATT&CK for Containersの**Initial Access**戦術に対応する4つの手法です。

---

## Lab 1: 公開Webアプリ脆弱性経由の侵入

- **MITRE ATT&CK for Containers**: T1190 (Exploit Public-Facing Application)
- **前提**: `vulnerable-webapp`（コマンドインジェクション可能なWebアプリ）を`vulnerable-webapp`というlabelの付いたPodにデプロイ

```bash
curl "http://vulnerable-webapp.lab.svc/ping?host=127.0.0.1;id"
```

このWebアプリは、ユーザー入力をそのままシェルに渡してしまう典型的な脆弱性を持っています。これにより、攻撃者はアプリケーションコンテナ内で任意コマンドを実行できます。

**Falcoの検知結果**:

```
17:42:03.112345000: Warning Unexpected shell in web container (user=www-data container=vulnerable-webapp command=sh -c id)
```

標準ルール `Terminal Shell in Container` が反応します。Webサーバコンテナで`sh`/`bash`が起動すること自体が異常、という前提のルールが効いている形です。

**Audit Logsの記録**: 対象外（Pod内で完結する操作のため、APIサーバへのリクエストは発生しない）

**考察**: この手法はアプリケーション層の脆弱性に起因しますが、**検知はコンテナ内の挙動（シェル起動）で行っている**点がポイントです。脆弱性そのものをFalcoが検知しているわけではなく、「脆弱性が悪用された結果として起きる異常な振る舞い」を捉えています。

## Lab 2: 誤設定・悪意あるイメージの実行

- **MITRE ATT&CK for Containers**: T1204.003 (Malicious Image), T1613 (Container and Resource Discovery の前段)
- **前提**: 公開レジストリから取得した、意図的にbackdoorを仕込んだイメージをデプロイ

```bash
kubectl run backdoor-test --image=ghcr.io/example-lab/backdoor-demo:latest
```

このイメージは起動時に外部IPへのコネクションを確立するように仕込まれています。

**Falcoの検知結果**:

```
17:45:11.903211000: Notice Outbound Connection to C2 Server (command=backdoor-agent connection=10.0.3.12:443->203.0.113.7:4444)
```

標準ルールセットには「既知の悪性IPへの通信」に反応するルールはデフォルトで含まれないため、**本書の実験用にカスタムルール（接続先IPリストとのマッチング）を追加**しています。

```yaml
- list: known_malicious_ips
  items: [203.0.113.7]

- rule: Outbound Connection to C2 Server
  desc: 既知の悪性IPへの通信
  condition: >
    outbound and fd.sip in (known_malicious_ips)
  output: >
    Outbound Connection to C2 Server (command=%proc.name connection=%fd.name)
  priority: CRITICAL
```

**考察**: 標準ルールだけでは検知できず、**脅威インテリジェンス（悪性IPリスト）と組み合わせて初めて検知可能**になった例です。これは第9章の研究A（検知カバレッジ）で「未検知の理由」として分類する典型パターンのひとつです。

## Lab 3: Kubelet誤公開APIの悪用

- **MITRE ATT&CK for Containers**: T1552.007 (Container API), T1610 (Deploy Container)
- **前提**: kubeletの読み取り専用ポート（10255）が誤って外部に公開された状態を再現

```bash
curl http://<node-ip>:10255/pods
curl -X POST http://<node-ip>:10250/run/<namespace>/<pod>/<container> -d "cmd=id"
```

kubelet APIが認証なしで公開されていると、クラスタ内のPod一覧取得や、任意コンテナへのコマンド実行が外部から可能になります。

**Falcoの検知結果**: **対象外（観測の空白）**

kubelet APIへのリクエストは、ノード上のkubeletプロセスが処理するものであり、通常のPodのsyscallとしては現れません。Falcoはこの種の「kubeletそのものへの攻撃」を直接検知する設計にはなっていません。

**Audit Logsの記録**: 対象外（kubelet APIはkube-apiserverを経由しないため、Audit Logsにも記録されません）

**考察**: これは第1章で触れた境界線の空白が実際に現れる例です。**kubelet APIは「ノード内」でも「APIサーバ経由」でもない、独立した攻撃対象領域**であり、本書のラボ構成（Falco + Audit Logs）だけでは検知できません。対策としては、kubelet自体の認証設定（`--anonymous-auth=false`）や、ネットワークポリシーでの10250/10255ポートの外部遮断が必要になります。検知ではなく予防で塞ぐべき穴、という結論です。

## Lab 4: kubeconfig／Secret漏洩経由の侵入

- **MITRE ATT&CK for Containers**: T1552.001 (Credentials In Files)
- **前提**: CI/CDパイプラインのログに誤ってkubeconfigが出力されていた、という想定で、漏洩したkubeconfigを使い外部から直接クラスタAPIにアクセス

```bash
export KUBECONFIG=./leaked-kubeconfig
kubectl get secrets -A
```

**Falcoの検知結果**: 対象外（この操作はクラスタ外から`kubectl`経由でAPIサーバに直接行われるため、ノード上のsyscallには現れない）

**Audit Logsの記録**:

```json
{
  "verb": "list",
  "objectRef": {"resource": "secrets", "namespace": ""},
  "user": {"username": "system:serviceaccount:ci:deploy-bot"},
  "sourceIPs": ["198.51.100.23"],
  "responseStatus": {"code": 200}
}
```

第2章で`secrets`リソースを`RequestResponse`レベルで記録する設定にしていたため、**漏洩した認証情報による不審な全Secret一覧取得**がAudit Logsにしっかり記録されています。ただし、これを「異常」と判定するにはAudit Logs単体では不十分で、**通常業務でのアクセスパターン（どのIPから、どの頻度で）とのベースライン比較が必要**です。

**考察**: ここはFalcoではなくAudit Logsが主役になる、明確な役割分担の例です。

---

## 本章のまとめ

| Lab | 手法 | Falco | Audit Logs | 観測できた層 |
|---|---|---|---|---|
| 1 | 公開Webアプリ脆弱性 | ✅ 検知 | - | ノード内 |
| 2 | 悪意あるイメージ | ⚠️ カスタムルールで検知 | - | ノード内 |
| 3 | kubelet誤公開API | ❌ 観測の空白 | ❌ 観測の空白 | **どちらにも属さない独立領域** |
| 4 | kubeconfig漏洩 | - | ✅ 検知（ただし異常判定には追加の文脈が必要） | APIサーバ |

4本の実験だけでも、**「ノード内で完結する攻撃」「APIサーバ経由の攻撃」「どちらでもない空白地帯」**という3パターンが早速現れました。次章では、侵入後にコンテナ内部で何が実行されるか（Execution）を見ていきます。
