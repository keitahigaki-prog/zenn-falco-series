# はじめに - Falco実践シリーズ

おめでとうございます！Falco実践シリーズの執筆環境が整いました。

## 📁 プロジェクト構造

```
zenn-falco-series/
├── books/
│   └── falco-practice-series/
│       ├── config.yaml                          # 本の設定
│       ├── chapter01-what-is-falco.md           # 第1回
│       ├── chapter02-falco-architecture.md      # 第2回
│       ├── chapter03-hands-on-quickstart.md     # 第3回
│       ├── chapter04-writing-rules-beginner.md  # 第4回
│       ├── chapter05-writing-rules-intermediate.md # 第5回
│       ├── chapter06-falcosidekick-visualization.md # 第6回
│       ├── chapter07-k8s-audit-integration.md   # 第7回
│       ├── chapter08-cicd-devsecops.md          # 第8回
│       ├── chapter09-production-deployment.md   # 第9回
│       └── chapter10-advanced-topics.md         # 第10回
├── articles/                                    # 個別記事用（オプション）
├── README.md                                    # プロジェクト概要
├── PUBLICATION_GUIDE.md                         # 公開手順の詳細ガイド
├── GETTING_STARTED.md                           # このファイル
└── setup-github.sh                              # GitHubセットアップスクリプト
```

## 🚀 クイックスタート

### 1. プレビューを確認

プレビューサーバーが既に起動しています：

```bash
# ブラウザで開く
open http://localhost:8000
```

または手動で起動：

```bash
cd ~/zenn-falco-series
npx zenn preview
```

### 2. 記事を執筆

エディタで章ファイルを開いて執筆します：

```bash
# 例：第1回を執筆
vim books/falco-practice-series/chapter01-what-is-falco.md
# または VS Code
code books/falco-practice-series/chapter01-what-is-falco.md
```

保存すると、プレビューに自動反映されます。

### 3. GitHubリポジトリを作成

```bash
cd ~/zenn-falco-series
./setup-github.sh
```

または手動で：

```bash
# GitHubで新しいリポジトリを作成後
git remote add origin https://github.com/YOUR_USERNAME/zenn-falco-series.git
git branch -M main
git add .
git commit -m "Initial commit: Falco実践シリーズのセットアップ"
git push -u origin main
```

### 4. Zennと連携

1. [Zenn Dashboard](https://zenn.dev/dashboard/deploys) にアクセス
2. 「リポジトリを連携する」をクリック
3. 作成したリポジトリ（zenn-falco-series）を選択

## 📝 執筆フロー

### 日々の執筆

```bash
# 1. 記事を編集
vim books/falco-practice-series/chapter01-what-is-falco.md

# 2. プレビュー確認（既に起動中なら不要）
npx zenn preview

# 3. 変更をコミット
git add .
git commit -m "第1回：執筆進捗"
git push
```

### 段階的な公開

#### 方法1: 本全体を公開

```yaml
# books/falco-practice-series/config.yaml
published: true
```

#### 方法2: 公開する章を制御

```yaml
# books/falco-practice-series/config.yaml
chapters:
  - chapter01-what-is-falco     # 公開
  # - chapter02-falco-architecture  # 非公開（コメントアウト）
```

#### 方法3: 個別記事として公開

```bash
npx zenn new:article --slug falco-01-what-is-falco
```

詳細は `PUBLICATION_GUIDE.md` を参照してください。

## 📚 各章の執筆ガイド

### 第1回：Falcoとは何か？

**目標文字数**: 2,000-3,000字

**主な内容**:
- Falcoの誕生背景
- Runtime Securityの重要性
- 他ツールとの比較
- ユースケース

**含めるべき要素**:
- 導入セクション（なぜこの連載を読むべきか）
- Falcoの基本概念
- 具体例
- 次回への導線

### 第2回：Falcoの基本動作

**目標文字数**: 2,500-3,500字

**主な内容**:
- Syscallベースのアーキテクチャ
- カーネルモジュール vs eBPF
- イベント検知の仕組み

**含めるべき要素**:
- アーキテクチャ図
- 技術的な詳細
- パフォーマンスへの影響

### 第3回：ハンズオン

**目標文字数**: 2,000-3,000字

**主な内容**:
- 環境構築
- 実際に動かす
- 検知を体験

**含めるべき要素**:
- ステップバイステップの手順
- 実行可能なコマンド
- スクリーンショット
- トラブルシューティング

### 第4-5回：ルール作成

**目標文字数**: 各3,000-4,000字

**主な内容**:
- ルールの書き方
- ベストプラクティス
- 実例

**含めるべき要素**:
- 完全に動作するルール例
- 解説
- よくある間違い

### 第6-7回：統合と連携

**目標文字数**: 各2,500-3,500字

**主な内容**:
- 他ツールとの連携
- 可視化
- 通知設定

**含めるべき要素**:
- 設定例
- ダッシュボード画像
- 実装手順

### 第8-10回：実践と発展

**目標文字数**: 各3,000-4,000字

**主な内容**:
- 実運用での考慮事項
- チーム連携
- 将来展望

**含めるべき要素**:
- 実例
- チェックリスト
- ベストプラクティス

## 💡 執筆のヒント

### コードブロック

````markdown
```yaml
# Falcoルールの例
- rule: Shell spawned in container
  desc: A shell was spawned in a container
  condition: container and proc.name in (bash, sh)
  output: Shell spawned (user=%user.name container=%container.name)
  priority: WARNING
```
````

### メッセージボックス

```markdown
:::message
重要なポイントや注意事項を強調
:::

:::message alert
警告や注意が必要な内容
:::
```

### 画像の挿入

```markdown
![説明テキスト](/images/falco-architecture.png)
```

画像は `/images/` ディレクトリに配置

### リンク

```markdown
[Falco公式サイト](https://falco.org/)
```

## 🎯 公開前チェックリスト

記事を公開する前に確認：

- [ ] タイトルが適切か
- [ ] 誤字脱字がないか
- [ ] コードサンプルが動作するか
- [ ] 画像が適切に表示されるか
- [ ] リンクが正しいか
- [ ] 前回・次回への導線があるか
- [ ] プレビューで表示確認
- [ ] メタデータ（topics, published等）が正しいか

## 📖 参考資料

### Zenn関連
- [Zenn CLIガイド](https://zenn.dev/zenn/articles/zenn-cli-guide)
- [Zenn Markdown記法](https://zenn.dev/zenn/articles/markdown-guide)
- [本の作成方法](https://zenn.dev/zenn/articles/how-to-create-book)

### Falco関連
- [Falco公式ドキュメント](https://falco.org/docs/)
- [Falco GitHub](https://github.com/falcosecurity/falco)
- [Falco Rules Repository](https://github.com/falcosecurity/rules)

## 🆘 困ったときは

### プレビューが表示されない

```bash
# サーバーを再起動
pkill -f "zenn preview"
npx zenn preview
```

### Git操作でエラー

```bash
# 現在の状態を確認
git status

# 変更を取り消す（注意！）
git reset --hard HEAD
```

### Zennに反映されない

1. GitHubとの連携を確認
2. `npx zenn validate` で構文チェック
3. config.yamlの設定を確認

## 🎉 次のステップ

1. ✅ 環境セットアップ完了
2. 📝 第1回の執筆を開始
3. 🌐 GitHubリポジトリの作成
4. 🔗 Zennとの連携
5. 🚀 第1回を公開
6. 📈 フィードバックを受けて改善

頑張ってください！素晴らしい連載になることを期待しています！

---

質問や問題がある場合は：
- `README.md` - プロジェクト概要
- `PUBLICATION_GUIDE.md` - 詳細な公開手順
