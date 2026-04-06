---
title: "第4章 フィールド完全理解"
---

# 第4章 フィールド完全理解

## 4.1 フィールド体系の全体像

Falcoのルール作成で最も重要な資産が、利用可能なフィールド（fields）の知識です。何を検出するか、どう検出するかは、最終的には「どのフィールドを条件判定に使用するか」に帰結します。

### フィールドの分類

Falcoの主要なフィールド群は、イベント源（source）と事象の種類に基づいて分類されます：

```
syscall source（システムコール監視）
├── proc系：プロセス関連情報
├── fd系：ファイルディスクリプタ関連
├── evt系：イベント本体（システムコール）
├── user系：ユーザー関連情報
├── container系：コンテナ関連情報
├── k8s系：Kubernetes関連情報
└── thread系：スレッド情報

k8s_audit source（Kubernetes監査ログ）
├── k8s系：Kubernetes API操作
├── user系：APIアクセスユーザー
└── ka系：Kubernetes監査ログ固有フィールド

その他のsource
└── source固有フィールド
```

本章では、最も利用頻度の高い `syscall` source のフィールドを深掘りします。

---

## 4.2 proc系フィールド：プロセス関連情報

プロセス関連フィールドは、実行中のプロセスとその祖先に関する情報を提供します。

### proc.name

実行されたプロセスの名前（バイナリ名）です。

```yaml
# プロセス名の完全一致
condition: proc.name = bash
condition: proc.name = python3

# 複数プロセスの確認
condition: proc.name in (bash, sh, python, ruby, perl)

# 否定形
condition: proc.name != sshd
```

**注意点**：`proc.name` はバイナリ名のみであり、フルパスではありません。

```
実行例：/usr/bin/python3 script.py
proc.name = python3  ✓（フルパスではない）
proc.name = /usr/bin/python3  ✗（マッチしない）
```

### proc.pname

親プロセス（parent process）の名前です。プロセスがどのプロセスから起動されたかを判定するのに使用します。

```yaml
# docker exec で bash が起動された場合
proc.name = bash and proc.pname = docker

# systemd が起動したサービス
proc.pname = systemd

# kubelet が起動したコンテナプロセス
proc.pname = containerd
```

本書の付録A「よく使うフィールド早見表」でさらに詳しく各フィールドを解説しています。
