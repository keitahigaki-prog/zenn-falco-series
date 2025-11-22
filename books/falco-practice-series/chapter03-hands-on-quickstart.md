---
title: "第3回：ローカル環境でFalcoを動かす（最速10分Hands-on）"
---

# ローカル環境でFalcoを動かす（最速10分Hands-on）

## この章で学ぶこと

- Docker Desktop / Kind / Minikubeでの環境構築
- Falcoのインストール方法
- `falco -r rules.yaml`の基本操作
- 実際に検知ログを出してみる

---

## 前提条件

以下のいずれかの環境が必要です：

- Docker Desktop
- Kind（Kubernetes in Docker）
- Minikube

:::message
この章では、最も簡単なDocker Desktopを使った方法を紹介します。
:::

## Falcoのインストール

### Docker Desktopの場合

```bash
# 執筆予定：インストールコマンド
```

### Kindの場合

```bash
# 執筆予定：インストールコマンド
```

### Minikubeの場合

```bash
# 執筆予定：インストールコマンド
```

## 基本操作

### Falcoの起動

```bash
# 執筆予定：起動コマンド
```

### ルールファイルの指定

```bash
falco -r rules.yaml
```

### ログの確認

```bash
# 執筆予定：ログ確認コマンド
```

## ハンズオン：実際に検知してみる

### ステップ1: コンテナを起動

```bash
docker run --rm -it alpine sh
```

### ステップ2: 危険な操作を実行

```bash
# コンテナ内で実行
touch /etc/shadow
```

### ステップ3: Falcoのアラートを確認

```bash
# 執筆予定：期待されるアラート出力
```

### ステップ4: 他の検知パターンを試す

```bash
# 執筆予定：追加のハンズオン例
```

## トラブルシューティング

### アラートが表示されない場合

### パーミッションエラーが出る場合

### カーネルモジュールが読み込めない場合

:::message
**執筆予定内容**
- よくあるエラーと解決方法
- 環境別のトラブルシューティング
:::

## まとめ

この章では、ローカル環境でFalcoを実際に動かし、検知を体験しました。

次章では、Falcoのルールを自分で書く方法を学びます。

---

## 参考資料

- [Falco Installation Guide](https://falco.org/docs/getting-started/installation/)
- [Falco Docker Image](https://hub.docker.com/r/falcosecurity/falco)
