# 記事公開ガイド

このドキュメントでは、Falco実践シリーズを段階的に公開する手順を説明します。

## 公開の流れ

```
執筆 → レビュー → プレビュー → コミット → プッシュ → Zenn連携 → 公開
```

## 事前準備

### 1. Zennアカウントとの連携

1. [Zenn](https://zenn.dev/)にログイン
2. [ダッシュボード](https://zenn.dev/dashboard)にアクセス
3. 「リポジトリから記事を管理」を選択
4. このGitHubリポジトリを連携

### 2. ローカル環境の確認

```bash
cd ~/zenn-falco-series
npm install
npx zenn preview
```

## 記事を段階的に公開する方法

### 方法A: chaptersの制御（推奨）

この方法では、`config.yaml`のchapters配列で公開する章を制御します。

#### 第1回のみ公開

```yaml
# books/falco-practice-series/config.yaml
chapters:
  - chapter01-what-is-falco
  # - chapter02-falco-architecture  # まだ公開しない
  # - chapter03-hands-on-quickstart
  # ... 以下も同様
```

#### 第1-2回を公開

```yaml
chapters:
  - chapter01-what-is-falco
  - chapter02-falco-architecture
  # - chapter03-hands-on-quickstart
  # ... 以下も同様
```

### 方法B: published フラグの制御

各章のフロントマターに `published` フラグを追加する方法もあります（ただし、Zennの「本」機能では全体で1つの`published`しか使えないため、この方法は個別記事向けです）。

### 方法C: 個別記事として公開

連載を「本」ではなく、個別の記事として公開する方法：

```bash
# 第1回を個別記事として作成
npx zenn new:article --slug falco-01-what-is-falco

# 既存のchapter01の内容をコピー
cp books/falco-practice-series/chapter01-what-is-falco.md articles/falco-01-what-is-falco.md
```

記事のフロントマターを編集：

```yaml
---
title: "第1回：Falcoとは何か？ - Runtime Securityの本質"
emoji: "🛡️"
type: "tech"
topics: ["kubernetes", "falco", "security", "devsecops"]
published: true
publication_name: "your_publication_name"  # オプション
---
```

## 公開チェックリスト

### 記事執筆時

- [ ] タイトルが適切か
- [ ] 誤字脱字がないか
- [ ] コードサンプルが動作するか
- [ ] 画像・図表が適切に表示されるか
- [ ] リンクが正しいか
- [ ] 前回・次回への導線が適切か

### 公開前

- [ ] ローカルでプレビュー確認
- [ ] `npx zenn preview` でレンダリング確認
- [ ] コミットメッセージが適切か
- [ ] config.yamlの設定が正しいか

### 公開後

- [ ] Zennで正しく表示されているか
- [ ] ソーシャルメディアで告知
- [ ] フィードバックの確認

## 具体的な公開手順

### 第1回の公開

```bash
# 1. 記事を執筆
vim books/falco-practice-series/chapter01-what-is-falco.md

# 2. config.yamlを編集（第1回のみ有効化）
vim books/falco-practice-series/config.yaml
# chapters:
#   - chapter01-what-is-falco
# published: true  # 公開する場合はtrue

# 3. プレビュー確認
npx zenn preview

# 4. コミット
git add .
git commit -m "第1回：Falcoとは何か？ - Runtime Securityの本質"

# 5. GitHubにプッシュ
git push origin main
```

### 第2回の追加公開

```bash
# 1. 記事を執筆
vim books/falco-practice-series/chapter02-falco-architecture.md

# 2. config.yamlに第2回を追加
vim books/falco-practice-series/config.yaml
# chapters:
#   - chapter01-what-is-falco
#   - chapter02-falco-architecture  # ← 追加

# 3. README.mdのステータスを更新
vim README.md
# | 第2回 | ... | ✅ 公開済み |

# 4. コミット＆プッシュ
git add .
git commit -m "第2回：Falcoの基本動作を理解する"
git push origin main
```

### 第3回以降

同様の手順で、1章ずつ公開していきます。

## GitHubリポジトリの管理

### ブランチ戦略

```
main                    ← 公開済みの記事
├── draft/chapter01     ← 執筆中の第1回
├── draft/chapter02     ← 執筆中の第2回
└── draft/chapter03     ← 執筆中の第3回
```

### コミットメッセージの規則

```
第N回：<タイトル>                    # 新規執筆完了
第N回：<変更内容>                    # 内容修正
Fix: 第N回の誤字修正                # 誤字脱字修正
Update: 第N回にコード例を追加       # 追記
```

## トラブルシューティング

### プレビューが表示されない

```bash
# node_modulesを再インストール
rm -rf node_modules package-lock.json
npm install
npx zenn preview
```

### Zennに反映されない

1. GitHubとの連携を確認
2. リポジトリのブランチが正しいか確認（通常はmain）
3. config.yamlの構文エラーを確認

```bash
# YAMLの構文チェック
npx zenn validate
```

### 画像が表示されない

Zennでは画像は以下のいずれかの方法で配置：

1. `/images/` ディレクトリに配置
2. 外部URLを使用（GitHub、Cloudinaryなど）

```markdown
<!-- ローカル画像 -->
![説明](/images/falco-architecture.png)

<!-- 外部URL -->
![説明](https://example.com/image.png)
```

## 公開スケジュール例

週1回ペースで公開する場合：

| 週 | 公開内容 | 公開日（例） |
|----|----------|--------------|
| 1週目 | 第1回 | 2025-12-01 |
| 2週目 | 第2回 | 2025-12-08 |
| 3週目 | 第3回 | 2025-12-15 |
| 4週目 | 第4回 | 2025-12-22 |
| 5週目 | 第5回 | 2025-12-29 |
| 6週目 | 第6回 | 2026-01-05 |
| 7週目 | 第7回 | 2026-01-12 |
| 8週目 | 第8回 | 2026-01-19 |
| 9週目 | 第9回 | 2026-01-26 |
| 10週目 | 第10回 | 2026-02-02 |

## Zennの「本」機能の特徴

- 複数の章をまとめて1つの本として公開できる
- 無料または有料（200-5000円）で公開可能
- 目次が自動生成される
- 読者は章ごとに読み進められる
- 全章を一度に公開する必要はなく、段階的に追加可能

## 参考リンク

- [Zenn CLIガイド](https://zenn.dev/zenn/articles/zenn-cli-guide)
- [Zenn本の作成方法](https://zenn.dev/zenn/articles/how-to-create-book)
- [ZennとGitHubの連携](https://zenn.dev/zenn/articles/connect-to-github)
