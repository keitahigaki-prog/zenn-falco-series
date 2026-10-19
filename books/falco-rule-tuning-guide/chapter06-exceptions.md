---
title: "第6章 例外設計 ― 「削らずに狭める」ための思想と技法"
---

# 第6章 例外設計 ― 「削らずに狭める」ための思想と技法

> この章の目的：Falco の例外（exception）を、ザル化させずに、必要な場所だけ狭く無効化できるようになる。

Falco の運用で最も判断が難しいのが「例外の入れ方」です。多くのチームがここで次の二択に迷います。

- 消しすぎて検知が効かなくなる（ザル化）
- 怖くて消せず、アラートが埋もれる（ノイズ疲弊）

この二択から抜け出すための鍵は、**例外を「削除」ではなく「範囲制御」と捉える** ことです。本章では、その考え方と、実際の書き方、よくある落とし穴、そして「本当に狭められたか」の検証までを、tuning-lab（Falco 0.45.0 / Helm chart 9.2.0 / modern_ebpf）上の実測で一気通貫に扱います。

## 6.1 例外とは何か

例外（exception）とは、**あるルールの condition にマッチする事象のうち、特定の属性を持つものだけを除外する仕組み** です。ルールそのものを無効化する`disabled: true`とは別物です。

| 手段 | 対象 | 影響範囲 | いつ使うか |
|---|---|---|---|
| `disabled: true` | ルール全体 | 全環境で検知が止まる | そのルールが不要と判断できる時 |
| `condition`をoverrideで書き換え | ルール全体 | 書き換え箇所に依存 | ルールの意味論自体を変えたい時 |
| `exceptions` + `override: {exceptions: append}` | 指定した属性を持つ事象のみ | 最小限 | 一部の正常挙動だけを除きたい時（本章の主役） |
| upstreamの`user_known_*`マクロを上書き | ルール全体 | マクロの範囲に依存 | upstreamが調整用に用意したフックがある時 |

迷ったらまず`exceptions`、それでも足りなければ`user_known_*`マクロの上書き、**最後の手段がdisable**、という順序感覚を持ってください。

## 6.2 ケーススタディ：7つの正常業務ワークロードをチューニングする

実際に、次の7種類の「攻撃ではないが upstream ルールを踏む」正常業務ワークロードをtuning-labに立てました（詳細は各ワークロードのマニフェストを参照）。

| ID | ワークロード | 踏むルール |
|---|---|---|
| N1 | 設定リローダー（コントローラがAPIサーバーをポーリング） | `Contact K8S API Server From Container` |
| N2b | 設定変換ジョブ（起動時にバイナリをダウンロードして実行） | `Drop and execute new binary in container` |
| N3b | 外形監視（ping で疎通確認） | `Redirect STDOUT/STDIN to Network Connection in Container` |
| N4 | コンプライアンスジョブ（`/etc/shadow`を読む） | `Read sensitive file untrusted` |
| N5 | シークレット混入チェック（grep） | `Search Private Keys or Passwords` |
| N6 | アプリのログローテーション | `Clear Log Activities` |
| N7 | SREのkubectl exec調査 | `Terminal shell in container` / `Packet socket created in container` |

何もチューニングしない状態で15分間動かしたところ、**15件のアラート**が出ました。これから1件ずつ、「削らずに狭める」を適用していきます。

### N1: namespace × pod label × イメージ × プロセス名で絞る

```yaml
- rule: Contact K8S API Server From Container
  exceptions:
    - name: apps_config_reloader
      fields: [k8s.ns.name, "k8s.pod.label[app]", container.image.repository, proc.name]
      values:
        - [apps, config-reloader, docker.io/curlimages/curl, curl]
  override:
    exceptions: append
```

4つのフィールドを**AND**で組み合わせることで、「`apps`ネームスペースの、`app=config-reloader`ラベルを持つPodの、`curlimages/curl`イメージで動く、`curl`プロセス」だけに絞っています。どれか1つでも違えば例外は効かず、ルールはちゃんと発火します。

### N2b: プロセス名ではなく実行パスで絞る

```yaml
- rule: Drop and execute new binary in container
  exceptions:
    - name: apps_config_render_yq
      fields: [k8s.ns.name, container.image.repository, proc.exepath]
      values:
        - [apps, docker.io/library/alpine, /usr/local/bin/yq]
  override:
    exceptions: append
```

`proc.name`（`yq`）ではなく`proc.exepath`（`/usr/local/bin/yq`）で絞っているのは、同名の別バイナリが別の場所に置かれて実行された場合まで許可したくないからです。「名前」より「パス」のほうが縛りとして狭い、という原則をここで押さえてください。

### N4: ジョブ名の前方一致で絞る

```yaml
- rule: Read sensitive file untrusted
  exceptions:
    - name: ops_password_expiry_audit
      fields: [k8s.ns.name, "k8s.pod.label[batch.kubernetes.io/job-name]", proc.name, fd.name]
      comps: ["=", startswith, "=", "="]
      values:
        - [ops, password-expiry-audit-, awk, /etc/shadow]
  override:
    exceptions: append
```

`exceptions`では、フィールドごとに比較演算子（`comps`）を変えられます。CronJobが生成するPodの名前は`password-expiry-audit-29872076-f5v9b`のようにサフィックスが付くため、ジョブ名のラベルは`startswith`で前方一致にしています。

### N6: namespace/labelで絞ると「race」で漏れることがある（実測で発見した落とし穴）

当初、N6（ログローテーション）の例外は次のように書きました。

```yaml
- macro: allowed_clear_log_files
  condition: >
    (k8s.ns.name = "apps"
     and k8s.pod.label[app] = "legacy-app"
     and fd.name = "/var/log/access.log")
```

ところがPodを再起動して実測したところ、**チューニングしたはずの`Clear Log Activities`が発火しました。** アラートの中身を見ると：

```json
{"rule":"Clear Log Activities",
 "output":"... file=/var/log/access.log ... container_name=host ... k8s_ns_name=<NA> ..."}
```

`k8s.ns.name`が`<NA>`（未解決）になっていました。Pod起動直後の短命なプロセスでは、**Kubernetesメタデータの解決がFalcoの検知に間に合わないことがある**のです。これは、姉妹本『攻撃して学ぶKubernetes Runtime Security』のLab 1で見つかった「`proc.pname`が短命プロセスでは`<NA>`になりやすい」という知見と同じ種類の現象です。

対処として、メタデータ解決に依存しない`fd.name`だけをキーにしました。

```yaml
- macro: allowed_clear_log_files
  condition: (fd.name = "/var/log/access.log")
```

**ただし、これにはトレードオフがあります。** このrace発生時は`container.image.repository`も同時に空になっていたため、イメージで絞り込んでも救えませんでした。結果として、「このファイルパスへの書き込みは丸ごと許可する」という、本来意図していたより広い例外になっています。本番で採用するなら、パス自体をワークロード固有にする（例：`emptyDir`のマウント先にワークロード名を含める）ことで埋め合わせる必要があります。

### N3b: ラベルより「pod名」のほうが解決が安定していた

N6と似た問題が、N3b（ping による外形監視）の例外でも起きました。当初のマクロです。

```yaml
- macro: user_known_stand_streams_redirect_activities
  condition: >
    (k8s.ns.name = "ops"
     and k8s.pod.label[app] = "uptime-checker"
     and proc.name = "ping"
     and proc.pname = "sh")
```

実測すると、同じイベントで`k8s.pod.name`は`"uptime-checker-7b757864bf-xwmsq"`と正しく解決されているのに、`k8s.pod.label[app]`だけが未解決（`<NA>`）になるケースを確認しました。**pod名とpodラベルは別系統のキャッシュで、ラベルのほうが解決に失敗しやすい**ようです。

`k8s.pod.label[app]`を`k8s.pod.name startswith "uptime-checker-"`に変え、`proc.pname`も`exists`で許容する形に直しても、**なお例外が効きませんでした。** 単体の切り分け用ルールで同じ条件を検証したところ、`proc.pname exists`／`not proc.pname exists`のどちらも発火しないという、原因を完全には特定しきれない挙動に行き当たりました（調査の過程は第5章で詳しく扱います）。

最終的に、マクロの上書きではなく、N1・N4・N5・N7で実績のある`exceptions`形式に統一することで解決しました。

```yaml
- rule: Redirect STDOUT/STDIN to Network Connection in Container
  exceptions:
    - name: ops_uptime_checker_ping
      fields: [k8s.ns.name, "k8s.pod.name", proc.name]
      comps: ["=", startswith, "="]
      values:
        - [ops, "uptime-checker-", ping]
  override:
    exceptions: append
```

> **この章の教訓**: 例外のキーには「解決の安定性」の序列があります。実測した範囲では `k8s.pod.name` > `k8s.pod.label[*]`。namespace自体も、ごく短命なプロセスでは未解決になり得るので、**本番の重要な例外ほど「メタデータに依存しない」フィールド（`fd.name`、`proc.exepath`など）を主キーにする**のが安全です。また、マクロの複合条件（`and`/`or`のネスト）が理論通りに動かないことも実際に起こり得ます。**同じ目的のチューニングを複数の書き方で実現できるなら、チーム内で実績のある書き方（本書では`exceptions`形式）に統一するほうが、原因不明の挙動に振り回されずに済みます。**

### N7: 「消さずに優先度を下げる」という第三の選択肢

```yaml
- rule: Terminal shell in container
  priority: INFORMATIONAL
  override:
    priority: replace
```

SREが`kubectl exec -it`で調査に入る行為そのものは、消したい誤検知ではなく「監査ログとして残したいが、毎回アラートが鳴るのは煩わしい」ものです。`exceptions`で消すのではなく、`priority`のoverride（第8章）で優先度だけを下げるという選択をしました。

## 6.3 結果：15件→2件、しかも攻撃検知は生きている

7種類の例外・override適用後、同じ15分間のノイズを再実行したところ、アラートは**2件**（SREの調査セッションによる`Terminal shell in container`、優先度はINFORMATIONALに下げ済み）まで減りました。

削りすぎていないかは、第9章で攻撃を再生して確認します。

## 6.4 例外設計のレビュー観点（チェックリスト）

- [ ] 例外のキーは何個のフィールドのANDで絞っているか。1〜2個だけなら広すぎないか疑う
- [ ] `proc.name`で絞っているなら、`proc.exepath`に変えられないか検討したか
- [ ] namespace/label/pod名などメタデータ系フィールドをキーにする場合、Pod起動直後の短命プロセスでも解決されるかを実測したか
- [ ] `exists`判定が必要なフィールド（`proc.pname`等）に、素朴な文字列比較だけで済ませていないか
- [ ] この例外は「攻撃者が模倣できる属性」で絞っていないか（例：`proc.cmdline`の完全一致だけだと、引数を1文字変えられて迂回される）
- [ ] 例外を追加したことで、本来検知したかった攻撃経路が塞がれていないか（第9章の回帰テストで確認する）
