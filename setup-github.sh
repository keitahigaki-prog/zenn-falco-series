#!/bin/bash

# GitHubリポジトリセットアップスクリプト
# このスクリプトは、ローカルリポジトリをGitHubにプッシュするための手順を案内します

set -e

echo "=========================================="
echo "Falco実践シリーズ - GitHubセットアップ"
echo "=========================================="
echo ""

# 現在のステータス確認
echo "📋 現在のGitステータス:"
git status
echo ""

# GitHub CLIの確認
if command -v gh &> /dev/null; then
    echo "✅ GitHub CLI (gh) が見つかりました"
    echo ""

    read -p "🤔 GitHub CLIを使ってリポジトリを作成しますか？ (y/n): " use_gh_cli

    if [ "$use_gh_cli" = "y" ]; then
        echo ""
        echo "📦 GitHubリポジトリを作成します..."

        read -p "リポジトリ名 (デフォルト: zenn-falco-series): " repo_name
        repo_name=${repo_name:-zenn-falco-series}

        read -p "公開設定 (public/private, デフォルト: public): " visibility
        visibility=${visibility:-public}

        # リポジトリ作成
        gh repo create "$repo_name" \
            --"$visibility" \
            --description "Falco実践シリーズ - Kubernetesランタイムセキュリティの実装ガイド" \
            --source=. \
            --remote=origin \
            --push

        echo ""
        echo "✅ GitHubリポジトリが作成され、コードがプッシュされました！"
        echo ""
        echo "🌐 リポジトリURL:"
        gh repo view --web

    else
        echo ""
        echo "⚠️  手動でGitHubリポジトリを作成してください"
        show_manual_steps
    fi
else
    echo "⚠️  GitHub CLI (gh) が見つかりません"
    echo "   インストール方法: https://cli.github.com/"
    echo ""
    echo "📝 手動でGitHubリポジトリを作成する手順:"
    show_manual_steps
fi

function show_manual_steps() {
    echo ""
    echo "=========================================="
    echo "手動セットアップ手順"
    echo "=========================================="
    echo ""
    echo "1. GitHubで新しいリポジトリを作成:"
    echo "   https://github.com/new"
    echo ""
    echo "   - Repository name: zenn-falco-series"
    echo "   - Description: Falco実践シリーズ - Kubernetesランタイムセキュリティの実装ガイド"
    echo "   - Public/Private: お好みで"
    echo "   - 「Initialize this repository with」のオプションはすべてチェックを外す"
    echo ""
    echo "2. 作成後、以下のコマンドを実行:"
    echo ""
    echo "   git remote add origin https://github.com/YOUR_USERNAME/zenn-falco-series.git"
    echo "   git branch -M main"
    echo "   git add ."
    echo "   git commit -m \"Initial commit: Falco実践シリーズのセットアップ\""
    echo "   git push -u origin main"
    echo ""
}

echo ""
echo "=========================================="
echo "次のステップ"
echo "=========================================="
echo ""
echo "1. Zennアカウントにログイン"
echo "   https://zenn.dev/"
echo ""
echo "2. ダッシュボードでGitHubリポジトリを連携"
echo "   https://zenn.dev/dashboard/deploys"
echo ""
echo "3. リポジトリ連携後、以下のファイルを編集:"
echo "   - books/falco-practice-series/config.yaml"
echo "     published: false → true に変更（公開時）"
echo ""
echo "4. ローカルでプレビュー:"
echo "   npx zenn preview"
echo ""
echo "5. 記事を執筆して公開:"
echo "   詳細は PUBLICATION_GUIDE.md を参照"
echo ""
echo "✨ 準備完了！素晴らしい記事を書いてください！"
