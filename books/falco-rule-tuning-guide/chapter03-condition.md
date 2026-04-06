---
title: "第3章 conditionを完全に理解する"
---

# 第3章 conditionを完全に理解する

## 3.1 ルール構文の全体像

Falcoのルールエンジンを理解するには、まずルール定義の全体構造を把握することが重要です。ひとつのルールは複数のフィールドで構成され、それぞれが異なる役割を担っています。

```yaml
- rule: Suspicious behavior in container
  desc: Detect suspicious process execution inside containers
  source: syscall
  tags: [container, process]
  enabled: true
  condition: >
    spawned_process and container.privileged = false and
    (proc.name in (bash, sh) or proc.cmdline contains "curl")
  output: >
    Process spawned in container (user=%user.name uid=%user.uid command=%proc.cmdline image=%container.image.repository)
  priority: WARNING
```

### ルール構文の各フィールド詳細

**rule（必須）**
ルール名です。Falcoの内部識別子として使用されます。ダッシュボードやアラート出力に表示されるため、運用では最も目にする部分です。命名規則は一般的に「What it detects」を英語で簡潔に記述します。

```yaml
rule: Terminal shell in container
rule: Write below root
rule: Suspicious file access pattern
```

**desc（必須）**
ルールの説明文です。何を検出するのか、なぜ重要なのかを1〜2文で記述します。ルール作成後に他のチームメンバーが参照することを想定して、実装の意図を明確に書きます。

**source（必須）**
ルールが監視対象にするイベント源です。現在のFalcoでは主に以下が使用されます：

- `syscall`: システムコール（最も一般的）
- `k8s_audit`: Kubernetes API監査ログ
- `aws_cloudtrail`: AWS CloudTrail
- `github`: GitHub監査ログ

**condition（必須）**
ルールがアラートを生成する条件です。これが本章の中心的テーマです。

本書では、conditionの読み方、論理構造の分解方法、演算子の使い分けについて詳しく解説します。
