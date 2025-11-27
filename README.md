# Falco実践シリーズ - Kubernetesランタイムセキュリティの実装ガイド

FalcoによるKubernetesランタイムセキュリティの基礎から実運用まで、10回の連載で段階的に学ぶ実践ガイドです。

## 連載構成

| 回 | タイトル | 公開状況 |
|----|----------|----------|
| 第1回 | [Falcoとは何か？ - Runtime Securityの本質](books/falco-practice-series/chapter01-what-is-falco.md) | ✅ 執筆完了 |
| 第2回 | [Falcoの基本動作を理解する（Syscalls × Rules）](books/falco-practice-series/chapter02-falco-architecture.md) | ✅ 執筆完了 |
| 第3回 | [ローカル環境でFalcoを動かす（最速10分Hands-on）](books/falco-practice-series/chapter03-hands-on-quickstart.md) | ✅ 執筆完了 |
| 第4回 | [Falcoのルールを書く（初心者編）](books/falco-practice-series/chapter04-writing-rules-beginner.md) | ✅ 執筆完了 |
| 第5回 | [Falcoのルールを書く（中級編）- 実運用に寄せる](books/falco-practice-series/chapter05-writing-rules-intermediate.md) | ✅ 執筆完了 |
| 第6回 | [Falcosidekick / UI可視化を入れてみる](books/falco-practice-series/chapter06-falcosidekick-visualization.md) | ✅ 執筆完了 |
| 第7回 | [K8s Audit Log × Falcoの連携](books/falco-practice-series/chapter07-k8s-audit-integration.md) | ✅ 執筆完了 |
| 第8回 | [Falco + CI/CD / DevSecOpsシナリオ](books/falco-practice-series/chapter08-cicd-devsecops.md) | ✅ 執筆完了 |
| 第9回 | [本番環境にFalcoを入れる時の設計](books/falco-practice-series/chapter09-production-deployment.md) | ✅ 執筆完了 |
| 第10回 | [Falcoの発展系（OPA Gatekeeper / Kyverno との比較）](books/falco-practice-series/chapter10-advanced-topics.md) | 📝 未執筆 |

## 開発環境

このリポジトリは[Zenn CLI](https://zenn.dev/zenn/articles/zenn-cli-guide)で管理されています。

### セットアップ

```bash
npm install
```

### プレビュー

```bash
npx zenn preview
```

ブラウザで `http://localhost:8000` を開くとプレビューが表示されます。

## 記事の公開フロー

### ステップ1: 記事の執筆

各章のマークダウンファイルを編集します：

```bash
# 例：第1回を執筆
vim books/falco-practice-series/chapter01-what-is-falco.md
```

### ステップ2: ローカルでプレビュー

```bash
npx zenn preview
```

### ステップ3: GitHubにプッシュ

```bash
git add .
git commit -m "第1回：執筆完了"
git push origin main
```

### ステップ4: Zennで公開

1. [Zenn Dashboard](https://zenn.dev/dashboard)にアクセス
2. GitHubリポジトリと連携
3. `config.yaml`の`published`を`true`に変更
4. 変更をプッシュすると自動的に公開されます

## 段階的な公開方法

連載を順次公開する場合：

### 方法1: chaptersの順序で制御

`config.yaml`のchapters配列に、公開したい章だけを記載します：

```yaml
chapters:
  - chapter01-what-is-falco  # 第1回だけ公開
  # - chapter02-falco-architecture  # コメントアウト
```

### 方法2: 個別記事として公開

bookではなく、articlesとして個別に公開することも可能です：

```bash
npx zenn new:article --slug falco-01-what-is-falco
```

## ディレクトリ構造

```
zenn-falco-series/
├── books/
│   └── falco-practice-series/
│       ├── config.yaml          # 本の設定ファイル
│       ├── chapter01-what-is-falco.md
│       ├── chapter02-falco-architecture.md
│       └── ...
├── articles/                    # 単独記事用（必要に応じて）
├── package.json
└── README.md
```

## コントリビューション

誤字脱字の修正や内容の改善提案は、Issueまたは Pull Request でお願いします。

## ライセンス

記事の内容は個人の見解であり、所属組織の公式見解ではありません。

## 参考リンク

- [Falco公式サイト](https://falco.org/)
- [Zenn CLIガイド](https://zenn.dev/zenn/articles/zenn-cli-guide)