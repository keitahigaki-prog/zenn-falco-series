---
title: "第5章 誤検知・過検知の調査フロー"
---

# 第5章 誤検知・過検知の調査フロー

本章では、Falcoのアラートを受け取ったときの調査の進め方を、tuning-labで実際に体験した「チューニングしたはずの例外が効いていない」というケースを通して説明します。架空の手順書ではなく、実際に筆者が詰まった過程をそのまま載せています。

## 5.1 調査の4ステップ

```
Step 1: outputのフィールドをすべて読む
    ↓
Step 2: ルールのcondition（第3章・第4章）のどの部分が真になったかを特定する
    ↓
Step 3: 「本当にそうなっているか」を、別の切り分け用ルールで実測する
    ↓
Step 4: 原因が完全には特定できなくても、実績のある別解に倒す判断をする
```

## 5.2 実例：N3bの例外が効かない

第6章で、`uptime-checker`の`ping`による`Redirect STDOUT/STDIN to Network Connection in Container`を、次のマクロ上書きで抑制しようとしました。

```yaml
- macro: user_known_stand_streams_redirect_activities
  condition: >
    (k8s.ns.name = "ops"
     and k8s.pod.name startswith "uptime-checker-"
     and proc.name = "ping"
     and (not proc.pname exists or proc.pname = "sh"))
```

### Step 1: outputを読む

適用後も、次のアラートが出続けました。

```json
{"rule":"Redirect STDOUT/STDIN to Network Connection in Container",
 "output_fields":{"proc.name":"ping","proc.pname":"<NA>",
                   "k8s.pod.name":"uptime-checker-7b757864bf-xwmsq","k8s.ns.name":"ops"}}
```

`k8s.ns.name`は`"ops"`、`k8s.pod.name`は`"uptime-checker-7b757864bf-xwmsq"`（`startswith`条件を満たす）、`proc.name`は`"ping"`。見た目上、マクロの条件はすべて満たされているはずです。

### Step 2: conditionのどこが効いていないかを疑う

残る疑わしい箇所は`proc.pname`の判定（`not proc.pname exists or proc.pname = "sh"`）です。`proc.pname`の表示は`"<NA>"`でした。第3章・第4章で見た通り、`<NA>`という表示と`exists`の真偽は別物なので、ここを疑いました。

### Step 3: 切り分け用ルールで実測する

マクロを疑うだけでなく、実際に単体のルールとして同じ条件を書いて確認しました。

```yaml
- rule: PNAME EXISTS CHECK
  desc: probe
  condition: evt.type=dup3 and proc.name="ping" and proc.pname exists
  output: "EXISTS-TRUE pname=%proc.pname"
  priority: NOTICE

- rule: PNAME NOTEXISTS CHECK
  desc: probe
  condition: evt.type=dup3 and proc.name="ping" and not proc.pname exists
  output: "EXISTS-FALSE pname=%proc.pname"
  priority: NOTICE
```

本来、この2つのルールは「どちらか一方が必ず真になる」はずです（`proc.pname`が存在するか、しないかのどちらかしかありません）。ところが実測では、**同じ`ping`の`dup3`イベントに対して、既存の`Redirect STDOUT/STDIN`ルールは確かに発火し続けているのに、この2つの切り分け用ルールはどちらも一度も発火しませんでした。**

この時点で分かったのは次の2点です。

- 少なくとも`evt.type`や`proc.name`の単純な比較自体は機能している（他のルールは正しく評価されているため）
- しかし`proc.pname exists` / `not proc.pname exists`という組み合わせが、期待した通りの二択として動いていない。原因は、マクロのネストしたand/or構造なのか、`exists`演算子とこの特定のフィールドの組み合わせなのか、この実験だけでは完全には切り分けられませんでした

### Step 4: 原因不明のまま、実績のあるパターンに倒す

ここで重要なのが**Step 4の判断**です。原因を完全に特定できないまま時間を使い続けるのではなく、「同じチューニングファイルの中で、すでに動作確認済みの書き方があるなら、そちらに統一する」という現実的な判断をしました。N1・N4・N5・N7では`exceptions` + `override: {exceptions: append}`の形式が実測で機能していたので、N3bも同じ形式に書き換えます。

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

これで実際にアラートが止まることを確認しました。

## 5.3 この経験から持ち帰るべきこと

- **「conditionが真になるはずなのに発火しない／しないはずなのに発火する」ことは、現実に起きる。** ルールエンジンの実装詳細まで完全に説明できなくても、運用上は前に進む必要があります
- **マクロでの複合条件（`and`/`or`のネスト）に不安を感じたら、同じロジックを単体の切り分け用ルールとして書き、実際に発火するか確認する。** 机上の読み解きだけで「このマクロは正しいはずだ」と判断しないことが、本章の最大の教訓です
- **同じ目的を達成する書き方が複数ある（マクロの上書き vs `exceptions`）なら、チーム内で実績のあるパターンに統一する。** 「理論的に正しいはずの書き方」より「実測で確認できた書き方」を優先してください

このような切り分け力は、第7章（upstreamルールの扱い方）でoverrideの挙動を検証した経験とも直結しています。「ルールが思った通りに動いているか」を常に実測で確認する姿勢こそが、本書全体を貫くチューニングの作法です。
