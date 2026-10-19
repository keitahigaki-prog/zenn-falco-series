---
title: "付録B: 例外パターン集"
---

# 付録B: 例外パターン集

第6章の「削らずに狭める」思想を、実務で転用しやすい形にまとめたものです。すべてtuning-labで実際に動作確認したパターンをベースにしています。コピーする前に、フィールド値を自分の環境のものに差し替えてください。

## B.1 namespace × pod名（前方一致）× プロセス名

CronJob/Jobが生成するPodは名前にサフィックスが付くため、`startswith`での前方一致が基本形です（第6章N4）。

```yaml
- rule: <対象ルール名>
  exceptions:
    - name: <namespace>_<workload>_<短い理由>
      fields: [k8s.ns.name, "k8s.pod.label[batch.kubernetes.io/job-name]", proc.name, fd.name]
      comps: ["=", startswith, "=", "="]
      values:
        - [<namespace>, "<job名>-", <プロセス名>, <パス>]
  override:
    exceptions: append
```

## B.2 イメージ × 実行パス（プロセス名より狭い粒度）

「名前」ではなく「パス」で縛ることで、同名バイナリが別の場所に置かれた場合まで許可しないようにします（第6章N2b）。

```yaml
- rule: Drop and execute new binary in container
  exceptions:
    - name: <namespace>_<workload>_<バイナリ名>
      fields: [k8s.ns.name, container.image.repository, proc.exepath]
      values:
        - [<namespace>, <イメージ>, </絶対パス/バイナリ名>]
  override:
    exceptions: append
```

## B.3 メタデータに依存しないキー（race を避けたい場合）

namespace/podラベルで絞ると、短命プロセスや起動直後でメタデータが未解決（race）になり、例外が効かないことがあります（第6章N6・N3b）。重要な例外ほど、`fd.name`や`proc.exepath`のようにコンテナランタイム自身が把握している値をキーにしてください。

```yaml
- macro: <upstreamのuser_known_*またはallowed_*マクロ名>
  condition: (fd.name = "/正確で衝突しにくいパス")
```

> トレードオフ: namespace/イメージでの絞り込みを諦めるため、本来より広い例外になります。パス自体をワークロード固有にする（emptyDirのマウント先にワークロード名を含める等）ことで埋め合わせてください。

## B.4 「消さずに優先度を下げる」パターン

誤検知ではなく、監査ログとしては残したいが通知の優先度を下げたい場合は、`exceptions`ではなく`priority`のoverrideを使います（第6章N7、第7章）。

```yaml
- rule: <対象ルール名>
  priority: INFORMATIONAL
  override:
    priority: replace
```

## B.5 書き方が複数ある場合は、実績のある方に統一する

第5章・第6章のN3bで実際に遭遇した通り、マクロの複合条件（`and`/`or`のネスト）が理論通りに動かないことがあります。同じ目的を`exceptions`形式でも実現できるなら、チーム内で動作実績のある書き方に統一してください。

```yaml
- rule: <対象ルール名>
  exceptions:
    - name: <識別子>
      fields: [k8s.ns.name, "k8s.pod.name", proc.name]
      comps: ["=", startswith, "="]
      values:
        - [<namespace>, "<pod名プレフィックス>-", <プロセス名>]
  override:
    exceptions: append
```

## 運用上の共通ルール

- 例外の`name`には、どのワークロードのどういう理由の除外かが分かる識別子を付ける（本書の命名例: `ops_uptime_checker_ping`）
- 1〜2個のフィールドだけで絞る例外は、広すぎないか疑う（本書の例は最低3フィールドのANDで構成）
- 第9章の回帰テストで、この例外が攻撃経路まで塞いでいないかを確認してから本番に反映する
- 対象ワークロードが廃止されたら、同じPRで例外も削除する（第10章）
