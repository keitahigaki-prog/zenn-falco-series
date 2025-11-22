---
title: "第6回：Falcosidekick / UI可視化を入れてみる"
---

# Falcosidekick / UI可視化を入れてみる

## この章で学ぶこと

- Falcosidekickを入れると何が変わる？（notifications）
- UIでルール単位で確認
- Grafanaダッシュボードで検知を可視化
- GitHubで公開されているダッシュボードの活用

---

## Falcosidekickとは

### Falco単体との違い

### Falcosidekickの役割

### アーキテクチャ

:::message
**執筆予定内容**
- Falcosidekickの概要
- なぜ必要なのか
- 主要な機能
:::

## Falcosidekickのインストール

### Helmを使ったインストール

```bash
# 執筆予定：インストールコマンド
```

### 設定ファイルのカスタマイズ

```yaml
# 執筆予定：values.yamlの例
```

## 通知先の設定

### Slack通知

```yaml
# 執筆予定：Slack設定例
```

### Microsoft Teams通知

```yaml
# 執筆予定：Teams設定例
```

### PagerDuty連携

```yaml
# 執筆予定：PagerDuty設定例
```

### その他の通知先一覧

| 通知先 | ユースケース | 設定の複雑さ |
|--------|--------------|--------------|
| Slack | 執筆予定 | 低 |
| Teams | 執筆予定 | 低 |
| PagerDuty | 執筆予定 | 中 |

:::message
**執筆予定内容**
- 各通知先の詳細設定
- どのような場合に使い分けるか
:::

## Falcosidekick UIの活用

### UIのインストール

```bash
# 執筆予定：UI インストールコマンド
```

### ダッシュボードの見方

### ルール単位での確認方法

### フィルタリング機能

:::message
**執筆予定内容**
- UIの機能紹介
- 実際の画面スクリーンショット
:::

## Grafanaダッシュボード

### Grafanaの準備

```bash
# 執筆予定：Grafana セットアップ
```

### Prometheusとの連携

```yaml
# 執筆予定：Prometheus 設定
```

### ダッシュボードのインポート

### カスタマイズ方法

:::message
**執筆予定内容**
- Grafanaダッシュボードの構築方法
- 公開されているダッシュボードの活用
- カスタムメトリクスの追加
:::

## 実践：エンドツーエンドの可視化

### ステップ1: アラート発生

### ステップ2: Slack通知

### ステップ3: UIで詳細確認

### ステップ4: Grafanaでトレンド分析

:::message
**執筆予定内容**
- 実際の運用フロー
- トラブルシューティング事例
:::

## まとめ

この章では、Falcosidekickを使った通知と可視化について学びました。

次章では、Kubernetes Audit Logとの連携について学びます。

---

## 参考資料

- [Falcosidekick Documentation](https://github.com/falcosecurity/falcosidekick)
- [Falcosidekick UI](https://github.com/falcosecurity/falcosidekick-ui)
- [Grafana Dashboards for Falco](https://grafana.com/grafana/dashboards/?search=falco)
