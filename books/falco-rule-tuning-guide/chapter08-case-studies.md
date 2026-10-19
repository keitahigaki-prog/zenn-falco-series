---
title: "第8章 実戦ケーススタディ"
---

# 第8章 実戦ケーススタディ

本章では、tuning-labおよび姉妹本『攻撃して学ぶKubernetes Runtime Security』のラボで実際に遭遇した4つのケースを扱います。いずれも「何が起きたか → 何を疑ったか → 実測でどう確認したか → 結論」の流れで書いています。

## ケース1: ルール名とアラート文の先頭は別物

### 状況

姉妹本のラボで、特権コンテナからhostPath経由で`/etc/shadow`を読み取る攻撃（`chroot /host cat /etc/shadow`）を再現したところ、次の2つが検知されました。

```
11:25:26.226 Critical Shell spawned without a tty (...)
11:25:26.238 Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow ...
```

執筆時点では「`Sensitive file opened for reading by non-trusted program`というルールがある」と書いていましたが、**upstreamの`falco_rules.yaml`を`grep -i`で確認しても、そういう名前の`rule:`は存在しませんでした。**

### 実測で確認したこと

`falco_rules.yaml`をJSON出力で検証すると、実際の`rule`フィールドは`Read sensitive file untrusted`でした。

```yaml
- rule: Read sensitive file untrusted
  output: Sensitive file opened for reading by non-trusted program | file=%fd.name ...
```

**`rule:`（ルール名）と`output:`の先頭文言は別物です。** プレーンテキストのログ出力には`output`テンプレートの文言しか表示されないため、ログだけを見ている人は「ルール名」としてこの文言を記憶してしまいがちです。実際、姉妹本の調査メモにも同じ取り違えが記録されていました。

### 結論

ルールを特定・override・exceptionsの対象にするときは、必ずJSON出力（`.rule`フィールド）か`falco_rules.yaml`の`rule:`行で名前を確認してください。アラート文面から推測した名前でoverrideを書くと、第7章で説明した「存在しないルール名へのoverride」エラーになります。

## ケース2: 「踏むはず」が外れた理由をis_exe_upper_layerで説明する

### 状況

第2章で触れた通り、「`pip install`でgunicornを入れて起動するアプリ」が`Drop and execute new binary in container`を踏むと想定しましたが、実測では一度も発火しませんでした。

### 実測で確認したこと

```yaml
condition: >
  spawned_process
  and container
  and proc.is_exe_upper_layer=true
  and not container.image.repository in (known_drop_and_execute_containers)
  and not known_drop_and_execute_activities
```

`proc.is_exe_upper_layer`は、overlayfsの「上位レイヤ（コンテナ起動後に書き込まれた差分）」に実行ファイルの実体があるかどうかを見ています。`pip install gunicorn`で入るのは`gunicorn`という**Pythonスクリプト**（shebangで`#!/usr/bin/env python3`を指す）で、実際にexecveされるのはベースイメージに最初から含まれる`python3.12`そのものです。つまり「新しい実行ファイルが実行された」のではなく「既存の実行ファイルが、新しく置かれた引数（スクリプト）を読んだ」だけなので、このルールの対象外です。

対照的に、姉妹本Lab 9の`apk add strace`（新しいELFバイナリがupperレイヤに置かれ、それ自体がexecveされる）では、同じルールが正しく発火しました。

### 結論

「upstreamルールが発火しない」ことに遭遇したら、まず「このワークロードは本当にルールの対象になる種類の事象を起こしているか」を疑ってください。インタプリタ経由のスクリプト実行と、ネイティブバイナリの実行は、ファイルシステムレベルでは全く違う事象です。

## ケース3: 複数のkindクラスタがあると、他クラスタのホストプロセスまで「検知」される

### 状況

tuning-labで、チューニング未適用のはずの`Contact K8S API Server From Container`が、自分が作っていないワークロードから大量に出ていました。

```json
{"rule":"Contact K8S API Server From Container",
 "output_fields":{"proc.name":"dragent","proc.cmdline":"dragent --noipcns",
                   "container.id":"8fb221fbced8","k8s.ns.name":null}}
```

### 実測で確認したこと

`dragent`はtuning-labのワークロードではなく、同じDocker Desktop上で動いていた**別のkindクラスタ**（`sysdig-handson`）のエージェントでした。`k8s.ns.name`が常に`null`（Kubernetesメタデータが解決されていない）であることが、「自クラスタの外のプロセス」を見分ける手がかりになります。modern_ebpfドライバは、ホストのLinuxカーネル全体のsyscallを観測するため、同じホスト上の他クラスタのコンテナのイベントまで拾ってしまうことがあります（第2章参照）。

### 結論

複数のラボ・クラスタを同じホストで動かす場合、集計スクリプトやダッシュボードには**自クラスタのコンテナIDでフィルタする処理が必須**です。これを忘れると、「何もしていないのにアラートが大量に出た」という誤った不安を抱くことになります。

## ケース4: 「原因不明」でも実績のある書き方に倒す（第5章の続き）

第5章・第6章で扱った、N3b（`ping`による外形監視）の例外がマクロの上書きでは効かず、`exceptions`形式に統一して解決した件も、本章の趣旨に沿ったケーススタディです。重複を避けるため詳細はそちらに譲りますが、要点だけ繰り返します。

- 条件が理論上は満たされているように見えても、実測では発火し続けることがある
- 単体の切り分け用ルールで仮説を検証し、それでも原因が完全には特定できないことがある
- そのときは、同じチューニングファイルの中で**実績のある別の書き方に統一する**判断が現実的

## まとめ

4つのケースに共通するのは、「upstreamのルール名・条件・アラート文面を、思い込みではなく実測で確認する」という姿勢です。本書のほぼ全ての主張がtuning-labでの実測に基づいているのも、この姿勢を体現するためです。
