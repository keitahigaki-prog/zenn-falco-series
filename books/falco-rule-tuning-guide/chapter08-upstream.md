---
title: "第8章 upstreamルールの扱い方"
---

# 第8章 upstreamルールの扱い方

## はじめに

Falco を本番環境で運用していると、必ず直面する課題があります。

「upstream（公式）ルールは定期的に更新されるが、こちらはカスタマイズしてある。どうやって両立させるか」

本章では、`falco_rules.yaml`（upstream）と `falco_rules.local.yaml`（ローカル）の役割分担から、override の仕組み、バージョン更新時の差分吸収まで、実践的な管理方法を解説します。

## 8.1 falco_rules.yaml と falco_rules.local.yaml の役割分担

### 基本的な構成

Falco の デフォルト設定では、2つのルールファイルが読み込まれます。

```
/etc/falco/
├── falco_rules.yaml         ← upstream（Falcoプロジェクトが提供）
├── falco_rules.local.yaml   ← ローカルカスタマイズ（組織が管理）
└── rules.d/
    ├── custom_rules.yaml    ← 追加ルール
    └── exceptions.yaml      ← exception定義
```

**ファイルの読み込み順序（重要）：**

```yaml
# /etc/falco/falco.yaml
rules_file:
  - /etc/falco/falco_rules.yaml        # 第1優先度
  - /etc/falco/falco_rules.local.yaml  # 第2優先度（override可能）
  - /etc/falco/rules.d/*.yaml          # 第3優先度（追加ルール）
```

**原則：**

| ファイル | 役割 | 管理者 | 更新頻度 |
|---------|-----|--------|---------|
| falco_rules.yaml | upstream提供のルール | Falcoプロジェクト | 月1~2回 |
| falco_rules.local.yaml | ローカルカスタマイズ | SREチーム | 随時 |
| rules.d/*.yaml | 組織固有のルール | セキュリティチーム | 随時 |

本章では、upstream との同期管理、override の仕組み、バージョン更新時の対応について詳しく解説しています。
