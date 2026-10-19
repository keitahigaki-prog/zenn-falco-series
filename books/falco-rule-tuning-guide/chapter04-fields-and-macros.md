---
title: "第4章 フィールド・マクロ・リスト"
---

# 第4章 フィールド・マクロ・リスト

第3章でconditionの全体構造を読みました。本章では、conditionを構成する3つの部品——**フィールド**（`proc.name`のような値）、**マクロ**（条件の断片に名前を付けたもの）、**リスト**（値の集合）——を、upstreamの`falco_rules.yaml`に実在する例だけを使って見ていきます。

## 4.1 フィールド：種類と「取れないことがある」という前提

フィールドは、イベントの種類（`source`）ごとに提供されるものが変わります。本書で扱うのは`source: syscall`（システムコールイベント）が中心です。

| 系統 | 代表的なフィールド | 何を表すか |
|---|---|---|
| `proc.*` | `proc.name`, `proc.pname`, `proc.cmdline`, `proc.exepath`, `proc.tty` | 実行中プロセスとその親の情報 |
| `fd.*` | `fd.name`, `fd.type`, `fd.sip`, `fd.typechar` | ファイルディスクリプタ（ファイル／ソケット）情報 |
| `evt.*` | `evt.type`, `evt.dir`, `evt.arg.flags` | システムコールそのもの |
| `container.*` | `container.id`, `container.image.repository` | コンテナ情報 |
| `k8s.*` | `k8s.pod.name`, `k8s.ns.name`, `k8s.pod.label[*]` | Kubernetesメタデータ |
| `user.*` | `user.name`, `user.uid`, `user.loginuid` | 実行ユーザー |

### proc.name とフルパスの違い

```yaml
# 実行例: /usr/bin/python3 script.py
proc.name = python3        # ✓ マッチする（バイナリ名のみ）
proc.name = /usr/bin/python3  # ✗ マッチしない
```

パスまで含めて絞りたいときは`proc.exepath`を使います。第6章のN2bで、`proc.name`（名前）ではなく`proc.exepath`（パス）で例外を絞った理由はここにあります。

似た名前の`proc.exe`と混同しないよう注意してください。`falco --list`で確認すると、`proc.exe`は「argv[0]（最初のコマンドライン引数）」であり、実行ファイルのフルパスではありません。フルパスが欲しいときは`proc.exepath`です。

### 「値が取れないことがある」フィールドには exists を使う

第3章でも扱いましたが、重要なので改めて強調します。`proc.pname`・`k8s.ns.name`・`k8s.pod.label[*]`のようなフィールドは、**短命なプロセスや起動直後のPodでは解決が間に合わず値が取れない**ことがあります。tuning-labでの実測（第6章）では、同じイベントの中で`k8s.pod.name`は正しく解決されているのに`k8s.pod.label[app]`だけが未解決、というケースも確認しました。

```yaml
# upstream の container_entrypoint マクロ（実在）
condition: >
  (not proc.pname exists
   or proc.pname in (runc:[0:PARENT], runc:[1:CHILD], runc, docker-runc, ...))
```

`not proc.pname exists`という書き方が、「値が取れないこと」を正当な一致として明示的に扱っている例です。自分でマクロを書くときも、「このフィールドは常に取れる」と決めつけず、`exists`で確認する癖をつけてください。

## 4.2 マクロ：条件の断片に名前を付ける

マクロは、conditionの一部を名前付きで再利用する仕組みです。upstreamの`Terminal shell in container`が使っている`shell_procs`を見てみます。

```yaml
- macro: shell_procs
  condition: (proc.name in (shell_binaries))
```

中身はたった1行で、`shell_binaries`という**リスト**（次節で説明）を`in`演算子で参照しているだけです。これを直接ルールに書かず、わざわざマクロにしている理由は、**同じ判定を複数のルールから再利用するため**です。実際、`shell_procs`は`Terminal shell in container`以外に`Run shell untrusted`など複数のルールから参照されています。マクロを1箇所直せば、それを使っている全ルールに反映されます。

もう一つ、第6章のチューニングで実際に上書きした`allowed_clear_log_files`を見てみます。

```yaml
# upstream のデフォルト（何にもマッチしない）
# a placeholder for whitelist log files that could be cleared.
#   Recommend the macro as (fd.name startswith "/var/log/app1*")
```

実はupstreamのコメントには具体的な条件の書き方すら書かれていません。**マクロの中には、最初から「ここを自分の環境向けに上書きしてください」という意図で空のまま用意されているものがある**のです。このようなマクロを見つけることが、第6章・第7章で行うチューニングの出発点になります。upstreamで同じパターンのマクロ名を探すには、次のように`never_true`を検索すると効率的です。

```bash
grep -B2 "condition: (never_true)" /etc/falco/falco_rules.yaml
```

tuning-labで実際にこのコマンドを実行すると、`known_drop_and_execute_activities`や`user_known_stand_streams_redirect_activities`など、`user_known_*`という命名規則のマクロが何個も見つかります。これらすべてが「チューニングの入口」です。

## 4.3 リスト：値の集合、判定ロジックは持たない

リストは純粋に値の集合です。upstreamの実例です。

```yaml
- list: sensitive_file_names
  items: [/etc/shadow, /etc/sudoers, /etc/pam.conf, /etc/security/pwquality.conf]
```

これを使うマクロが`sensitive_files`です。

```yaml
- macro: sensitive_files
  condition: >
    (fd.name in (sensitive_file_names) or
      fd.directory in (/etc/sudoers.d, /etc/pam.d))
```

ここで「リスト＋マクロ」の分業が見えます。**リストは『何を』、マクロは『どう判定するか』を担当します。** `sensitive_files`マクロは、`sensitive_file_names`リストに載っているファイルへの完全一致**に加えて**、`/etc/sudoers.d`や`/etc/pam.d`配下というディレクトリ単位の判定も組み合わせています。単なる値の列挙では表現できない判定ロジックをマクロ側に書く、という役割分担です。

### リストはリストを参照できる

upstreamの`k8s_containers`マクロは、複数のリストをまとめて`in`で参照しています。

```yaml
- macro: k8s_containers
  condition: >
    (container.image.repository in (gcr.io/google_containers/hyperkube-amd64, ...,
     falco_containers,
     falco_no_driver_containers,
     ibm_cloud_containers, ...)
     or (k8s.ns.name = "kube-system"))
```

`falco_containers`や`ibm_cloud_containers`はそれ自体が別のリストです。このように、リストを分割しておくことで、「クラウドベンダーごとの既知コンポーネント」のように管理主体が異なる集合を、個別に更新できるようにしています。自分のチームで`known_internal_tools`のようなリストを作るときも、この粒度感を参考にしてください。

## 4.4 まとめ

- フィールドには「取れないことがある」ものが存在する（`proc.pname`、`k8s.pod.label[*]`等）。比較の前に`exists`を検討する
- マクロは条件の再利用単位。`never_true`で検索すると、upstreamが用意した「チューニングの入口」が見つかる
- リストは値の集合、判定ロジックはマクロ側が持つ。管理主体が違う集合は別リストに分ける
