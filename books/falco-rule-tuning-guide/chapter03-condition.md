---
title: "第3章 conditionを完全に理解する"
---

# 第3章 conditionを完全に理解する

本章では、架空の例ではなく **upstreamの`falco_rules.yaml`に実在するルール** を素材にします。検証環境は Falco 0.45.0（Helm chart `falcosecurity/falco` 9.2.0、`driver.kind: modern_ebpf`）です。バージョンが変われば条件式の細部も変わるので、手元の環境で `falco --list` や実際のアラート出力を見ながら読み進めてください。

## 3.1 ルール構文の全体像

ひとつのルールは複数のフィールドで構成されます。題材として、upstreamに実在する`Terminal shell in container`を使います。

```yaml
- rule: Terminal shell in container
  desc: >
    A shell was used as the entrypoint/exec point into a container with an attached terminal.
    Parent process may have legitimately already exited and be null (read container_entrypoint macro).
    Common when using "kubectl exec" in Kubernetes.
  condition: >
    spawned_process
    and container
    and shell_procs
    and proc.tty != 0
    and container_entrypoint
    and not user_expected_terminal_shell_in_container_conditions
  output: >
    A shell was spawned in a container with an attached terminal (user=%user.name user_loginuid=%user.loginuid
    %container.info shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline terminal=%proc.tty
    container_id=%container.id image=%container.image.repository)
  priority: NOTICE
  tags: [maturity_stable, container, shell, mitre_execution, T1059]
```

| フィールド | 役割 |
|---|---|
| `rule` | ルール名。アラート出力の`rule`フィールドにそのまま載る。同名のルールは「同一ルールの定義」として扱われ、2回目以降は上書き・追記になる（第8章で詳説） |
| `desc` | 説明文。`priority`より上に書くのが慣習 |
| `condition` | アラートを出す条件。本章の主題 |
| `output` | アラート本文のテンプレート。`%フィールド名`で値を埋め込む |
| `priority` | `EMERGENCY`〜`DEBUG`の8段階 |
| `tags` | MITRE ATT&CKのテクニックIDなど。`falco --list`での絞り込みにも使う |

これを実際にビルドして `kubectl exec -it` で確認すると、次のように出力されます（tuning-labでの実測）。

```json
{"rule":"Terminal shell in container","priority":"Notice",
 "output_fields":{"k8s.pod.name":"netshoot-7f474c7f47-wrmcg","k8s.ns.name":"ops",
 "container.image.repository":"docker.io/nicolaka/netshoot","proc.tty":1234, ...}}
```

## 3.2 conditionを構成要素に分解する

`Terminal shell in container`のconditionは、`and`で6つの要素をつないだものです。一つずつ見ていきます。

```
spawned_process
and container
and shell_procs
and proc.tty != 0
and container_entrypoint
and not user_expected_terminal_shell_in_container_conditions
```

**①②: `spawned_process and container`** — 「新しいプロセスが」「コンテナ内で」起きたことを表すフィルタです。`spawned_process`自体もマクロで、内部的には`evt.type in (execve, execveat) and evt.dir=<`（成功したexecve系イベント）を指します。ほぼ全てのプロセス起動系ルールの先頭に付くので、暗記して構いません。

**③: `shell_procs`** — マクロで、中身は`proc.name in (shell_binaries)`。`shell_binaries`は`bash, csh, ksh, sh, tcsh, zsh, dash`などのリストです。「シェル」を直接 `proc.name in (bash, sh, ...)` と書かず、わざわざマクロ＋リストに分けているのは、同じ判定を他のルールからも再利用するためです（例：`Run shell untrusted`も同じ`shell_procs`を使う）。

**④: `proc.tty != 0`** — **ここが本章でいちばん重要な一行です。** `proc.tty`は、プロセスに端末(TTY)が割り当てられていれば非ゼロ、割り当てられていなければ`0`になります。つまりこの条件は「対話的に起動されたシェルだけ」を対象にしています。

> **実測: この条件がすり抜けを生む瞬間**
> tuning-labで、Webアプリのコマンドインジェクション経由で`id`を実行させたところ（TTYなし）、`Terminal shell in container`は**発火しませんでした**。`proc.tty`が`0`のままだったからです。代わりに発火したのは、`ping`がrawソケットをfd 0にdup3したことによる`Redirect STDOUT/STDIN to Network Connection in Container`でした。
>
> この条件式を読めていないと、「`Terminal shell in container`さえ有効にしておけば対話的侵入は検知できる」と誤解し、**プログラム的に起動されたシェル（Webアプリ経由のコマンドインジェクションなど）が検知対象外であることに気づけません。** `kubectl exec -it`のような対話的侵入と、脆弱性悪用のような非対話的侵入は、別のルールが担当しているのです。

**⑤: `container_entrypoint`** — もう一つの重要なマクロです。中身は次の通りです。

```yaml
- macro: container_entrypoint
  condition: >
    (not proc.pname exists
     or proc.pname in (runc:[0:PARENT], runc:[1:CHILD], runc, docker-runc,
                       exe, docker-runc-cur, containerd-shim, systemd, crio, conmon))
```

ここで使われている `not proc.pname exists` という書き方に注目してください。`proc.pname`（親プロセス名）は、**親プロセスがすでに終了してFalcoのプロセスキャッシュから消えていると取得できない**ことがあります。そのとき`exists`は偽になります。つまりこのマクロは「親プロセス名が分からない（コンテナランタイムが起動した直後で親がすぐ終了した）、または親がコンテナランタイム自身である」ことを「コンテナのentrypointとして妥当」と判定しています。

> **実測で踏んだ落とし穴: `exists`と`<NA>`は別物**
> `proc.pname`が取得できないとき、JSON出力では文字列`"<NA>"`として表示されます。しかし **`proc.pname = "<NA>"`という比較と`not proc.pname exists`は等価ではありません。** 実際にtuning-labで両方を別ルールとして仕込み、同一イベントで検証したところ、`proc.pname`が本当に未解決のときは `proc.pname exists` が偽（＝`not proc.pname exists`が真）になり、文字列比較`proc.pname = "<NA>"`は意図通りには機能しませんでした。upstreamのマクロが律儀に`exists`演算子を使っているのはこのためです。自分で例外マクロを書くときも、「値が無いかもしれない」フィールドは`exists`で明示的に判定してください（第6章で再度扱います）。

**⑥: `not user_expected_terminal_shell_in_container_conditions`** — upstreamが用意した「調整用の穴」です。デフォルトの中身は次の通りで、何もマッチしません。

```yaml
- macro: user_expected_terminal_shell_in_container_conditions
  condition: (never_true)
```

このマクロを自分の環境向けに上書きするのが、チューニング作業の基本形です。やり方は第6章・第8章で扱います。

## 3.3 他のルールで条件の「型」を確認する

もう一つだけ、違う型のconditionを見ておきます。`Contact K8S API Server From Container`です。

```yaml
condition: >
  evt.type=connect
  and (fd.typechar=4 or fd.typechar=6)
  and container
  and k8s_api_server
  and not k8s_containers
  and not user_known_contact_k8s_api_server_activities
```

- `evt.type=connect` — プロセス起動系ではなく、ネットワーク接続のイベントを見ている（`spawned_process`ではなく`evt.type=`で直接指定するパターン）
- `fd.typechar=4 or fd.typechar=6` — IPv4/IPv6ソケットに限定
- `k8s_api_server` — マクロで`fd.sip.name="kubernetes.default.svc.cluster.local"`。宛先がKubernetes APIサーバーかどうかの判定
- `not k8s_containers` — `k8s_containers`は「Kubernetesの管理コンポーネントとして既知のイメージ」のリスト（`kube-state-metrics`や`cert-manager`など）＋`k8s.ns.name = "kube-system"`。**ここが既存のよくある誤検知源です**。自作のコントローラやオペレータは当然このリストに載っていないため、APIサーバーに接続するだけで発火します（tuning-labのN1 `config-reloader`で実測済み）

条件式を読むときは、まず`and`で区切って要素に分け、各要素が「マクロ」なのか「フィールド比較」なのかを見分け、マクロなら中身まで展開する――この手順を機械的に繰り返すだけです。慣れてくると、ルール名とdescを読む前にconditionだけで「何を検知したいルールか」が分かるようになります。

## 3.4 まとめ

- conditionは`and`/`or`/`not`で繋がれた要素の集合。要素は「フィールド比較」か「マクロ」のどちらか
- `exists`演算子と、値が取得できないときの表示上の`<NA>`は別物。比較する前に`exists`で存在を確認する癖をつける
- upstreamルールの多くには`not user_known_*`や`not user_expected_*`という「常にnever_true」の調整用フックが付いている。これを見つけたら、それが本章で言う「チューニングの入口」である
