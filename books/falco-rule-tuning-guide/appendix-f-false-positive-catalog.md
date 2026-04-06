---
title: "付録F: よくある誤検知パターン集"
---

# 付録F: よくある誤検知パターン集

Falco導入時に頻出する誤検知パターン（false positive）を収集・分類しました。各パターンの原因と対処方法、例外設定例を掲載しています。

---

## パターン1: シェルのコマンド実行

**パターン名**: shell_spawned_with_execve
**発火するルール**: Suspicious Process (or similar execution rule)

**原因**:
- シェル（bash, sh, zsh）からの通常のコマンド実行
- 管理者による手動コマンド実行
- スクリプトの実行

**推奨対処**:
```yaml
# マクロに追加
- macro: shell_commands_from_shell
  condition: >
    proc.name in (bash, sh, zsh, ksh) and
    proc.pname in (bash, sh, zsh, ksh)

# ルール側で除外
condition: >
  (other_condition) and
  not shell_commands_from_shell
```

**注意点**:
- 正当なシェル実行とマルウェアによるシェル実行の区別は困難
- コンテナ内でのシェル実行は特に注意（init コンテナ、管理用 Pod）
- ホワイトリストの粒度：コマンド名ではなく「シェルの子プロセス」で判定

---

## パターン2: パッケージマネージャーの実行

**パターン名**: package_manager_execution
**発火するルール**: Write below root (apt-get, yum, pacman など)

**原因**:
- apt-get, yum, dnf による package install
- pip, npm, gem などの言語別パッケージマネージャー
- 正当な環境構築時の実行

本書では、さらに多くの誤検知パターンと対処方法を掲載しており、実運用での即座の対応に役立ちます。
