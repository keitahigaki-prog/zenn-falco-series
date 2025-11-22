---
title: "第8回：Falco + CI/CD / DevSecOpsシナリオ"
---

# Falco + CI/CD / DevSecOpsシナリオ

## この章で学ぶこと

- CI/CD中のコンテナもFalcoで守れるか
- ランタイム検知とイメージ署名の境界線
- IaCとdrift detectionの話
- tfdrift-falcoの紹介

---

## CI/CDパイプラインとセキュリティ

### Shift Leftの考え方

### ランタイムセキュリティの位置づけ

### DevSecOpsパイプラインの全体像

:::message
**執筆予定内容**
- CI/CDにおけるセキュリティの重要性
- 各段階でのセキュリティ対策
- Falcoの役割
:::

## CI/CD中のコンテナ監視

### ビルドステージでの監視

```yaml
# 執筆予定：GitHub Actions での Falco 統合例
```

### テストステージでの監視

```yaml
# 執筆予定：テスト環境での Falco 設定
```

### デプロイメントステージでの監視

:::message
**執筆予定内容**
- CI/CDの各段階でFalcoを活用する方法
- 実際のパイプライン例
:::

## ランタイム検知 vs イメージ署名

### それぞれの役割

| 手法 | 検知タイミング | 強み | 弱み |
|------|----------------|------|------|
| イメージ署名（Cosign等） | 執筆予定 | 執筆予定 | 執筆予定 |
| ランタイム検知（Falco） | 執筆予定 | 執筆予定 | 執筆予定 |

### 補完的な関係

### 両方使うべき理由

:::message
**執筆予定内容**
- イメージ署名とランタイム検知の違い
- それぞれが防げる脅威
- 統合的なセキュリティ戦略
:::

## Infrastructure as Codeとセキュリティ

### IaCにおけるセキュリティ課題

### Drift Detectionとは

### ランタイム検知との関連

:::message
**執筆予定内容**
- IaCのセキュリティベストプラクティス
- Drift Detection の重要性
- Falcoとの組み合わせ方
:::

## tfdrift-falcoの紹介

### tfdrift-falcoとは

### アーキテクチャ

```
[Terraform] → [Drift Detection] → [Falco] → [Alert]
```

### 使い方

```bash
# 執筆予定：tfdrift-falco の使用例
```

### ユースケース

1. Terraform管理下のリソースへの直接変更を検知
2. Compliance違反の即座の通知
3. GitOpsとの統合

:::message
**執筆予定内容**
- tfdrift-falco の詳細な説明
- 実際の使用例
- 他のツールとの比較
:::

## 実践：DevSecOpsパイプラインの構築

### ステップ1: Falcoの統合

### ステップ2: ポリシーの定義

### ステップ3: CI/CDパイプラインへの組み込み

### ステップ4: モニタリングとアラート

:::message
**執筆予定内容**
- 実際のパイプライン構築手順
- ベストプラクティス
- トラブルシューティング
:::

## GitOpsとの統合

### FluxとFalco

### ArgoCDとFalco

### Policy as Code

:::message
**執筆予定内容**
- GitOps環境でのFalco活用
- ポリシーのGit管理
- 自動化戦略
:::

## まとめ

この章では、CI/CDとDevSecOpsにおけるFalcoの活用方法を学びました。

次章では、本番環境へのデプロイメント設計について学びます。

---

## 参考資料

- [tfdrift-falco GitHub Repository](https://github.com/yourusername/tfdrift-falco)
- [Falco in CI/CD](https://falco.org/docs/integrations/)
- [Sigstore Cosign](https://github.com/sigstore/cosign)
