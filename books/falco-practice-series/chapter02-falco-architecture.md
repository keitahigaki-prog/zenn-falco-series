---
title: "第2回：Falcoの基本動作を理解する（Syscalls × Rules）"
---

# Falcoの基本動作を理解する（Syscalls × Rules）

## この章で学ぶこと

- Syscallベースのアーキテクチャ
- カーネルモジュール vs eBPFの違い
- 主要検知例（execve, chmod, mount）
- event-sourceの種類（k8s audit / container / syscall）

---

## Syscallベースのアーキテクチャ

:::message
**執筆予定内容**
- Syscallとは何か
- Falcoがどのようにシステムコールを監視するか
- データフローの全体像
:::

## カーネルモジュール vs eBPF

### カーネルモジュール方式

### eBPF方式

### どちらを選ぶべきか

:::message
**執筆予定内容**
- 両者の技術的な違い
- パフォーマンスへの影響
- 環境ごとの推奨
:::

## 主要な検知例

### execve - プロセス実行の検知

```yaml
# 執筆予定：サンプルルール
```

### chmod - 権限変更の検知

```yaml
# 執筆予定：サンプルルール
```

### mount - ファイルシステム操作の検知

```yaml
# 執筆予定：サンプルルール
```

## Event Sourceの種類

### Syscall Events

### Kubernetes Audit Events

### Container Events

:::message
**執筆予定内容**
- 各Event Sourceの特徴
- どのような場合に使い分けるか
- 複数のEvent Sourceを組み合わせる方法
:::

## まとめ

この章では、Falcoの内部アーキテクチャとイベント検知の仕組みについて学びました。

次章では、実際にローカル環境でFalcoを動かしてみます。

---

## 参考資料

- [Falco Architecture Documentation](https://falco.org/docs/architecture/)
- [eBPF Documentation](https://ebpf.io/)
