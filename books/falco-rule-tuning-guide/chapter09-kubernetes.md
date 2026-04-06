---
title: "第9章 Kubernetesで詰まりやすいポイント"
---

# 第9章 Kubernetesで詰まりやすいポイント

Falcoを本格的にKubernetesで運用する際、実装の実装は単なるコンテナ監視では済みません。本章では、K8sの複雑性に起因する誤検知やルール設計上の陥りやすい落とし穴を、具体的なYAML例とともに解説します。

## 9.1 namespaceスコープでの例外設計と落とし穴

Kubernetesではnamespaceという論理的な隔離単位が存在します。よくありがちなのは、特定のnamespace内の活動は「安全」と判断し、単純なフィルタリングで除外してしまうパターンです。

### 問題ケース：kube-system内なら何でも許可

```yaml
# 悪い例：namespace単位での過度に広い除外
- rule: Suspicious Shell in Container
  desc: Detects shell spawning in containers
  condition: >
    spawned_process and container and shell_spawned
    and not (ka.namespace.name in (kube_system, kube_public))
  output: >
    Suspicious shell (user=%user.name image=%container.image)
  priority: WARNING
  enabled: true

# 問題点：
# 1. kube-system内なら何でも許可される
# 2. Pod内のkube-system名前空間リソースまで対象外になる可能性
# 3. セキュリティリスク：侵害されたシステムコンポーネントの活動が見えない
```

本章では、Kubernetes環境特有の複雑性—— メタデータ取得のタイミング問題、Init Container / Sidecar の扱い、イメージ名・タグの揺れ、CI/CDジョブ由来のノイズなど——を詳しく解説しています。
