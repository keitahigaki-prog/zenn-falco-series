---
title: "付録B: 条件式チートシート"
---

# 付録B: 条件式チートシート

Falco ルール作成時の条件式（condition）文法をまとめたリファレンスです。演算子、論理演算、優先順位、実践的なパターンを掲載しています。

## 比較演算子

| 演算子 | 意味 | 例 | 備考 |
|---|---|---|---|
| `=` | 完全一致 | `proc.name = "bash"` | 大文字小文字は区別 |
| `!=` | 不一致 | `proc.name != "curl"` | != の反対が = |
| `<` | より小さい | `evt.time < 1000000` | 数値/文字列で動作 |
| `<=` | 以下 | `fd.lport <= 1024` | 特権ポート判定など |
| `>` | より大きい | `proc.uid > 0` | root 判定の逆（非root） |
| `>=` | 以上 | `file.size >= 1000000` | ファイルサイズ判定 |
| `glob` | ワイルドカード match | `proc.name glob "python*"` | `*` でマッチ |
| `startswith` | 接頭辞 | `fd.name startswith "/tmp"` | パスプレフィックス判定 |
| `endswith` | 接尾辞 | `fd.name endswith ".sh"` | ファイル拡張子判定 |
| `contains` | 部分文字列 | `proc.cmdline contains "curl"` | 部分一致 |
| `in` | リスト内 | `proc.name in (bash, sh, dash)` | 複数値の or |

## 論理演算子

| 演算子 | 意味 | 優先度 | 例 |
|---|---|---|---|
| `and` | AND | 3 | `a = 1 and b = 2` |
| `or` | OR | 2 | `a = 1 or b = 2` |
| `not` | NOT | 4（最高） | `not (a = 1)` |

本書では、よく使うパターン集として、実践的な条件式の書き方をさらに多数掲載しています。
