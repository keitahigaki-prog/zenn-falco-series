---
title: "第7回：K8s Audit Log × Falcoの連携"
---

# K8s Audit Log × Falcoの連携

## この章で学ぶこと

- syscallとauditの違い（どちらも重要）
- K8s audit webhookの設定
- kubectl操作をすべて監査し、Falcoで検知
- 実践的なauditルールの作成

---

## Syscall vs Kubernetes Audit

### Syscallイベントの特徴

### Kubernetes Auditイベントの特徴

### 両方必要な理由

:::message
**執筆予定内容**
- 検知できる範囲の違い
- 相互補完的な関係
- どちらか一方では不十分な理由
:::

## Kubernetes Audit Logとは

### Audit Logの基本

### Audit Policyの設定

```yaml
# 執筆予定：audit policy の例
```

### Audit Logの出力形式

:::message
**執筆予定内容**
- Kubernetes Audit Logの仕組み
- 監査レベル（None, Metadata, Request, RequestResponse）
- パフォーマンスへの影響
:::

## Audit Webhookのセットアップ

### Minikubeでの設定

```bash
# 執筆予定：minikube での設定コマンド
```

### EKSでの設定

```bash
# 執筆予定：EKS での設定方法
```

### GKEでの設定

```bash
# 執筆予定：GKE での設定方法
```

### AKSでの設定

```bash
# 執筆予定：AKS での設定方法
```

## Falcoとの連携

### Falcoの設定変更

```yaml
# 執筆予定：falco の audit 設定
```

### Audit Webhook Backend の構築

```yaml
# 執筆予定：webhook backend の設定
```

## Auditルールの作成

### 実例1: RoleBinding変更の検知

```yaml
# 執筆予定：RoleBinding 変更検知ルール
```

### 実例2: Secret取得の監査

```yaml
# 執筆予定：Secret アクセス検知ルール
```

### 実例3: Pod削除の検知

```yaml
# 執筆予定：Pod 削除検知ルール
```

### 実例4: 特権的な操作の検知

```yaml
# 執筆予定：特権操作検知ルール
```

## ハンズオン：kubectl操作を検知する

### ステップ1: Audit Webhookの有効化

### ステップ2: 検知ルールの適用

### ステップ3: kubectl操作の実行

```bash
kubectl get secrets -n kube-system
kubectl create rolebinding test-binding --role=admin --user=test-user
```

### ステップ4: アラートの確認

:::message
**執筆予定内容**
- 実際のハンズオン手順
- 期待される出力
- トラブルシューティング
:::

## 本番運用のポイント

### ログ量の管理

### 重要なイベントの優先順位付け

### アラート疲れの防止

:::message
**執筆予定内容**
- Audit Log の運用ベストプラクティス
- パフォーマンスチューニング
- コスト最適化
:::

## まとめ

この章では、Kubernetes Audit LogとFalcoを連携させる方法を学びました。

次章では、CI/CDとDevSecOpsへの統合について学びます。

---

## 参考資料

- [Kubernetes Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Falco K8s Audit Rules](https://github.com/falcosecurity/plugins/tree/main/plugins/k8saudit)
