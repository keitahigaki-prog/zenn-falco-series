---
title: "付録A: 条件式チートシート"
---

# 付録A: 条件式チートシート

Falco 0.45.0で実際に確認した構文のみを掲載しています。バージョンが変われば演算子が増減することがあるので、手元の環境で`falco --list`を実行して最新の対応状況を確認してください。

## 比較演算子

| 演算子 | 意味 | 例 |
|---|---|---|
| `=` | 完全一致 | `proc.name = "bash"` |
| `!=` | 不一致 | `proc.name != "curl"` |
| `<` `<=` `>` `>=` | 数値・文字列比較 | `fd.lport <= 1024` |
| `glob` | ワイルドカード一致 | `proc.name glob "python*"` |
| `startswith` | 前方一致 | `k8s.pod.name startswith "uptime-checker-"`（第6章N3bで実測使用） |
| `endswith` | 後方一致 | `fd.name endswith ".sh"` |
| `contains` | 部分一致 | `proc.cmdline contains "curl"` |
| `icontains` | 大文字小文字を無視した部分一致 | upstreamの`private_key_or_password`マクロで使用（`proc.args icontains "BEGIN PRIVATE"`） |
| `in` | 列挙値のいずれかに一致 | `proc.name in (bash, sh, dash)` |
| `exists` | フィールドに値が取得できているか | `proc.pname exists`（第3章・第4章参照） |

### `exists` は本書で最も重要な演算子

第3章・第6章で繰り返し扱った通り、`proc.pname`・`k8s.ns.name`・`k8s.pod.label[*]`のようなフィールドは、短命なプロセスや起動直後のPodで値が取得できないことがあります。upstreamの`container_entrypoint`マクロも`not proc.pname exists`という書き方で、この「値が無い」状態を明示的に扱っています。

```yaml
condition: (not proc.pname exists or proc.pname in (runc, containerd-shim, ...))
```

**ただし、第5章で実測した通り、`exists`を使っても必ずしも理論通りに動くとは限りません。** 複合条件（`and`/`or`のネスト）の中で`exists`を使う場合は、単体の切り分け用ルールで実際に発火するかを確認する習慣をつけてください。

## 論理演算子

| 演算子 | 意味 | 優先度 |
|---|---|---|
| `not` | 否定 | 最も高い |
| `and` | 論理積 | 次 |
| `or` | 論理和 | 最も低い |

優先度があるため、`a and b or c`は`(a and b) or c`と解釈されます。意図が紛らわしい場合は、括弧で明示してください（upstreamのマクロも、複数条件を括弧で囲む書き方を徹底しています）。

## よく使う組み合わせパターン

```yaml
# パターン1: namespace × pod名（前方一致）× プロセス名で絞る（第6章N3b/N4）
k8s.ns.name = "ops" and k8s.pod.name startswith "uptime-checker-" and proc.name = "ping"

# パターン2: イメージ × 実行パスで絞る（proc.nameより狭い。第6章N2b）
container.image.repository = "docker.io/library/alpine" and proc.exepath = "/usr/local/bin/yq"

# パターン3: メタデータに依存しないキー（race の影響を受けにくい。第6章N6）
fd.name = "/var/log/access.log"
```
