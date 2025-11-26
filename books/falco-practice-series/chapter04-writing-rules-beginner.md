---
title: "第4回：Falcoのルールを書く（初心者編）"
---

# Falcoのルールを書く（初心者編）

第3回でFalcoを実際に動かし、既存のルールで脅威を検知できることを体験しました。この章では、いよいよ**自分でルールを書く**方法を学びます。

Falcoルールは、YAMLファイルで記述するシンプルな構造ですが、奥が深く、適切に書かないと誤検知だらけになったり、重要な脅威を見逃したりします。この章では、初心者が陥りがちな罠を避けながら、実用的なルールを書く基礎を習得します。

## この章で学ぶこと

- ✅ Falcoルールの基本構造（rule, condition, output, priority）
- ✅ macro（マクロ）とlist（リスト）の活用法
- ✅ 実践的なルール例（5パターン）
- ✅ よくある失敗パターンと対策
- ✅ トラブルシューティングの考え方

---

## Falcoルールの基本構造

Falcoのルールは、**5つの必須要素**で構成されます。

### 最小のルール例

```yaml
- rule: Detect Shell in Container
  desc: Detect if a shell is spawned in a container
  condition: >
    spawned_process and
    container and
    proc.name in (sh, bash, zsh)
  output: >
    Shell spawned in container
    (user=%user.name container=%container.name
     image=%container.image.repository shell=%proc.name)
  priority: WARNING
```

### 5つの必須要素

| 要素 | 説明 | 必須 |
|------|------|------|
| `rule` | ルール名（一意） | ✅ |
| `desc` | ルールの説明 | ✅ |
| `condition` | 検知条件（Falco式） | ✅ |
| `output` | アラート出力フォーマット | ✅ |
| `priority` | 優先度レベル | ✅ |

### オプション要素

| 要素 | 説明 | 使用例 |
|------|------|--------|
| `tags` | タグ（分類用） | `[container, shell, security]` |
| `enabled` | 有効/無効 | `false` で無効化 |
| `warn_evttypes` | 警告するイベントタイプ | デバッグ用 |
| `skip-if-unknown-filter` | フィルタ不明時のスキップ | 後方互換性用 |

---

## condition（条件式）の書き方

`condition` は、Falcoが監視するシステムコールを**どう判定するか**を定義する最も重要な部分です。

### 基本的な演算子

```yaml
condition: >
  proc.name = bash          # 等価
  proc.name != bash         # 不等価
  proc.name in (sh, bash)   # リスト内に存在
  proc.name startswith /bin # 前方一致
  proc.name contains tmp    # 部分一致
  proc.name endswith .sh    # 後方一致
```

### 論理演算子

```yaml
condition: >
  spawned_process and                    # AND（かつ）
  container and                          # AND
  (proc.name = sh or proc.name = bash)  # OR（または）
```

### 否定

```yaml
condition: >
  spawned_process and
  not proc.name in (sh, bash)  # shとbash以外
```

### よく使う条件パターン

#### パターン1: プロセス起動を検知

```yaml
condition: >
  spawned_process and
  proc.name = curl
```

**解説:**
- `spawned_process` - 新しいプロセスが起動した
- `proc.name = curl` - プロセス名が `curl`

#### パターン2: ファイルアクセスを検知

```yaml
condition: >
  open_write and
  fd.name startswith /etc/
```

**解説:**
- `open_write` - ファイルを書き込みモードで開いた
- `fd.name startswith /etc/` - ファイル名が `/etc/` で始まる

#### パターン3: コンテナ内の動作を検知

```yaml
condition: >
  spawned_process and
  container and
  proc.name = apt-get
```

**解説:**
- `container` - コンテナ内での実行
- コンテナ外（ホスト）での apt-get は検知しない

#### パターン4: 特定ユーザーの動作を検知

```yaml
condition: >
  spawned_process and
  user.name = root and
  proc.name in (nc, netcat, ncat)
```

**解説:**
- `user.name = root` - rootユーザーが実行
- ネットキャット系ツールの実行を検知

---

## output（出力フォーマット）の書き方

`output` は、アラートが発生したときに**何を表示するか**を定義します。

### 基本フォーマット

```yaml
output: >
  メッセージ本文
  (フィールド1=%変数1 フィールド2=%変数2)
```

### よく使う出力フィールド

| フィールド | 説明 | 例 |
|-----------|------|-----|
| `%user.name` | 実行ユーザー | `root` |
| `%proc.name` | プロセス名 | `bash` |
| `%proc.cmdline` | コマンドライン全体 | `bash -c ls` |
| `%proc.pid` | プロセスID | `12345` |
| `%container.name` | コンテナ名 | `web-app` |
| `%container.id` | コンテナID | `abc123...` |
| `%container.image.repository` | イメージ名 | `nginx` |
| `%fd.name` | ファイル名 | `/etc/passwd` |
| `%evt.time` | イベント時刻 | `15:30:45` |

### 実践的な出力例

```yaml
output: >
  Shell spawned in container
  (user=%user.name
   command=%proc.cmdline
   container=%container.name
   image=%container.image.repository
   shell=%proc.name)
```

**出力結果:**
```
15:30:45: Warning Shell spawned in container
(user=root command=bash container=web-app-1
 image=nginx shell=bash)
```

---

## priority（優先度）の使い分け

優先度は、アラートの**深刻度**を表します。

### 優先度レベル

| レベル | 用途 | 例 |
|--------|------|-----|
| `EMERGENCY` | システム全体が危険 | カーネルモジュール改ざん |
| `ALERT` | 即座に対応が必要 | rootkit検知 |
| `CRITICAL` | 重大な脅威 | コンテナエスケープ |
| `ERROR` | エラー状態 | 認証失敗の繰り返し |
| `WARNING` | 警告（調査推奨） | シェル起動、パッケージインストール |
| `NOTICE` | 通知 | 設定変更 |
| `INFORMATIONAL` | 情報 | プロセス起動 |
| `DEBUG` | デバッグ情報 | 詳細ログ |

### 優先度の選び方

```yaml
# CRITICAL: 直ちに対応すべき
priority: CRITICAL
# 例: 特権コンテナでのシェル起動

# WARNING: 調査が必要
priority: WARNING
# 例: 通常コンテナでのシェル起動

# NOTICE: 記録しておく
priority: NOTICE
# 例: 設定ファイルの読み取り
```

---

## macro（マクロ）とlist（リスト）の活用

複雑な条件を再利用可能にするために、`macro` と `list` を使います。

### list（リスト）: 値の集合

```yaml
- list: shell_binaries
  items: [sh, bash, zsh, ksh, csh, tcsh, fish]

- list: sensitive_files
  items: [/etc/shadow, /etc/passwd, /etc/sudoers]
```

**使用例:**

```yaml
condition: proc.name in (shell_binaries)
condition: fd.name in (sensitive_files)
```

### macro（マクロ）: 条件式の部品

```yaml
- macro: container
  condition: container.id != host

- macro: spawned_process
  condition: evt.type = execve and evt.dir=<

- macro: interactive_shell
  condition: >
    spawned_process and
    proc.name in (shell_binaries) and
    proc.tty != 0
```

**使用例:**

```yaml
condition: >
  interactive_shell and
  container
```

### macro + list の組み合わせ

```yaml
# リスト定義
- list: package_managers
  items: [apt, apt-get, yum, dnf, apk, npm, pip]

# マクロ定義
- macro: package_mgmt_procs
  condition: proc.name in (package_managers)

# ルールで使用
- rule: Package Management in Container
  condition: >
    spawned_process and
    container and
    package_mgmt_procs
  output: >
    Package management tool executed
    (user=%user.name command=%proc.cmdline
     container=%container.name)
  priority: ERROR
```

---

## 実例1：curlの実行を検知する

最も基本的な例として、コンテナ内での `curl` 実行を検知するルールを書きます。

### ルール

```yaml
- list: http_client_binaries
  items: [curl, wget, fetch]

- rule: HTTP Client Tool in Container
  desc: Detect when HTTP client tools are executed in a container
  condition: >
    spawned_process and
    container and
    proc.name in (http_client_binaries)
  output: >
    HTTP client tool executed in container
    (user=%user.name command=%proc.cmdline
     container=%container.name image=%container.image.repository)
  priority: WARNING
  tags: [container, network, security]
```

### テスト方法

```bash
# ルールファイルを作成
cat > http_client_rule.yaml <<'EOF'
- list: http_client_binaries
  items: [curl, wget, fetch]

- rule: HTTP Client Tool in Container
  desc: Detect when HTTP client tools are executed in a container
  condition: >
    spawned_process and
    container and
    proc.name in (http_client_binaries)
  output: >
    HTTP client tool executed in container
    (user=%user.name command=%proc.cmdline
     container=%container.name image=%container.image.repository)
  priority: WARNING
  tags: [container, network, security]
EOF

# Falcoを起動（カスタムルールを読み込み）
docker run --rm -i -t \
  --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /proc:/host/proc:ro \
  -v $(pwd)/http_client_rule.yaml:/etc/falco/rules.d/http_client_rule.yaml \
  falcosecurity/falco:latest

# 別ターミナルでテスト
docker run --rm -it alpine sh -c "apk add curl && curl https://example.com"
```

### 期待される出力

```
15:45:12.123456789: Warning HTTP client tool executed in container
(user=root command=curl https://example.com
 container=sharp_pike image=alpine)
```

---

## 実例2：機密ファイルの読み取りを検知する

`/etc/shadow` や `/etc/passwd` などの機密ファイルへのアクセスを検知します。

### ルール

```yaml
- list: sensitive_files
  items:
    - /etc/shadow
    - /etc/passwd
    - /etc/sudoers
    - /root/.ssh/id_rsa
    - /root/.aws/credentials

- macro: open_read
  condition: >
    evt.type in (open, openat, openat2) and
    evt.is_open_read=true and
    fd.typechar='f'

- rule: Read Sensitive File
  desc: Detect reads to sensitive files
  condition: >
    open_read and
    fd.name in (sensitive_files) and
    not proc.name in (ps, systemd, sshd)
  output: >
    Sensitive file opened for reading
    (user=%user.name command=%proc.cmdline
     file=%fd.name container=%container.name)
  priority: WARNING
  tags: [filesystem, security, compliance]
```

### テスト方法

```bash
# Alpineコンテナで実行
docker run --rm -it alpine sh

# コンテナ内で実行
cat /etc/shadow
cat /etc/passwd
```

### 期待される出力

```
15:50:30.123456789: Warning Sensitive file opened for reading
(user=root command=cat /etc/shadow file=/etc/shadow
 container=eloquent_morse)
```

---

## 実例3：コンテナ内でのSSHサーバー起動を検知

コンテナ内でSSHサーバーが起動されることは、攻撃者が永続化や遠隔操作を試みている可能性があります。

### ルール

```yaml
- list: ssh_server_binaries
  items: [sshd, ssh-agent, ssh-keygen]

- rule: SSH Server Started in Container
  desc: Detect SSH server starting inside a container
  condition: >
    spawned_process and
    container and
    proc.name in (ssh_server_binaries)
  output: >
    SSH server process started in container
    (user=%user.name command=%proc.cmdline
     container=%container.name image=%container.image.repository)
  priority: CRITICAL
  tags: [container, network, persistence]
```

### テスト方法

```bash
# Ubuntu コンテナで実行
docker run --rm -it ubuntu bash

# コンテナ内で実行
apt-get update && apt-get install -y openssh-server
/usr/sbin/sshd
```

---

## 実例4：環境変数の読み取りを検知

環境変数には、API キーやデータベースパスワードなどの機密情報が含まれることがあります。

### ルール

```yaml
- list: env_readers
  items: [env, printenv, export]

- macro: suspicious_env_read
  condition: >
    spawned_process and
    proc.name in (env_readers)

- rule: Environment Variables Dumped
  desc: Detect when environment variables are dumped
  condition: >
    suspicious_env_read and
    container
  output: >
    Environment variables accessed
    (user=%user.name command=%proc.cmdline
     container=%container.name)
  priority: WARNING
  tags: [container, security, credentials]
```

### テスト方法

```bash
docker run --rm -it alpine sh

# コンテナ内で実行
env
printenv
```

---

## 実例5：特権コンテナの検知

特権コンテナ（`--privileged`）は、ホストへのフルアクセス権を持ち、非常に危険です。

### ルール

```yaml
- rule: Privileged Container Started
  desc: Detect when a container is started in privileged mode
  condition: >
    container and
    container.privileged=true
  output: >
    Privileged container started
    (user=%user.name container=%container.name
     image=%container.image.repository)
  priority: CRITICAL
  tags: [container, security, compliance]
```

### テスト方法

```bash
# 特権コンテナを起動
docker run --rm -it --privileged alpine sh
```

---

## よくある失敗パターン

### 失敗パターン1: 条件が広すぎる（誤検知多発）

**悪い例:**

```yaml
- rule: Process Executed
  condition: spawned_process  # すべてのプロセス起動を検知
  output: Process started (command=%proc.cmdline)
  priority: WARNING
```

**問題点:**
- すべてのプロセス起動が検知される
- アラートが多すぎて重要なものが埋もれる

**改善例:**

```yaml
- rule: Suspicious Process Executed
  condition: >
    spawned_process and
    container and
    proc.name in (nc, ncat, netcat, socat)  # 特定のプロセスのみ
  output: Suspicious network tool executed (command=%proc.cmdline)
  priority: WARNING
```

### 失敗パターン2: 条件が狭すぎる（見逃し）

**悪い例:**

```yaml
- rule: Shell in Container
  condition: >
    spawned_process and
    container and
    proc.name = bash  # bashのみ
  output: Shell detected
  priority: WARNING
```

**問題点:**
- `sh`, `zsh`, `fish` などは検知されない

**改善例:**

```yaml
- list: shell_binaries
  items: [sh, bash, zsh, ksh, fish, csh, tcsh]

- rule: Shell in Container
  condition: >
    spawned_process and
    container and
    proc.name in (shell_binaries)  # すべてのシェルをカバー
  output: Shell detected (shell=%proc.name)
  priority: WARNING
```

### 失敗パターン3: outputが不適切

**悪い例:**

```yaml
output: "Something happened"  # 情報不足
```

**問題点:**
- 誰が何をしたか不明
- 調査に必要な情報がない

**改善例:**

```yaml
output: >
  Shell spawned in container
  (user=%user.name
   command=%proc.cmdline
   container=%container.name
   image=%container.image.repository
   pid=%proc.pid
   parent=%proc.pname)
```

### 失敗パターン4: 正規の動作を除外していない

**悪い例:**

```yaml
- rule: File Written to /etc
  condition: >
    open_write and
    fd.name startswith /etc/
  output: File written to /etc (file=%fd.name)
  priority: WARNING
```

**問題点:**
- システムの正常な動作（設定変更など）も検知される

**改善例:**

```yaml
- list: known_system_writers
  items: [systemd, dpkg, apt, yum]

- rule: File Written to /etc
  condition: >
    open_write and
    fd.name startswith /etc/ and
    not proc.name in (known_system_writers)  # 正規プロセスを除外
  output: Unexpected file write to /etc (file=%fd.name user=%user.name)
  priority: WARNING
```

---

## トラブルシューティング

### 問題1: ルールが発火しない

**原因候補:**

1. **conditionの構文エラー**
   ```bash
   # Falcoのログを確認
   docker logs <falco-container> 2>&1 | grep -i error
   ```

2. **イベントがconditionに一致していない**
   ```yaml
   # デバッグ用：条件を緩めて確認
   condition: spawned_process  # 最小条件でテスト
   ```

3. **ルールが読み込まれていない**
   ```bash
   # ルールファイルのマウント確認
   docker run ... -v $(pwd)/my_rule.yaml:/etc/falco/rules.d/my_rule.yaml
   ```

**デバッグ手順:**

```yaml
# ステップ1: 最小のルールで動作確認
- rule: Test Rule
  desc: Test if rule is loaded
  condition: spawned_process
  output: Any process spawned (command=%proc.cmdline)
  priority: DEBUG

# ステップ2: 徐々に条件を追加
condition: spawned_process and container
condition: spawned_process and container and proc.name = curl
```

### 問題2: 誤検知が多すぎる

**対策:**

1. **ホワイトリストを追加**
   ```yaml
   - list: allowed_processes
     items: [systemd, kubelet, dockerd]

   condition: >
     suspicious_activity and
     not proc.name in (allowed_processes)
   ```

2. **特定のコンテナを除外**
   ```yaml
   - list: trusted_images
     items: [nginx, redis, postgres]

   condition: >
     suspicious_activity and
     not container.image.repository in (trusted_images)
   ```

3. **優先度を下げる**
   ```yaml
   priority: NOTICE  # WARNING → NOTICE に下げる
   ```

### 問題3: パフォーマンスが悪化

**原因:**
- 複雑すぎるcondition
- すべてのイベントを監視している

**対策:**

1. **条件を最適化**
   ```yaml
   # 悪い例（すべてのopenイベントを評価）
   condition: evt.type = open

   # 良い例（特定のパスのみ）
   condition: >
     evt.type = open and
     fd.name startswith /etc/
   ```

2. **不要なルールを無効化**
   ```yaml
   - rule: Noisy Rule
     enabled: false  # 無効化
   ```

---

## 演習問題

### 演習1: 基本ルールの作成

以下の条件を検知するルールを作成してください：

1. コンテナ内で `rm -rf` が実行された
2. コンテナ内で `.sh` ファイルが実行された
3. `/tmp` ディレクトリに実行可能ファイルが作成された

### 演習2: macro/listの活用

以下をmacro/listを使って実装してください：

1. データベースクライアント（mysql, psql, mongo）のリスト
2. ネットワークツール（nc, nmap, tcpdump）のmacro
3. 上記を使ったルール

### 演習3: 誤検知の削減

以下のルールは誤検知が多すぎます。改善してください：

```yaml
- rule: File Modified
  condition: >
    evt.type in (open, openat) and
    evt.is_open_write=true
  output: File modified (file=%fd.name)
  priority: WARNING
```

**ヒント:**
- 特定のディレクトリに限定
- システムプロセスを除外
- ファイルの拡張子でフィルタ

---

## まとめ

この章では、Falcoルールの基本的な書き方を学びました。

### 学んだこと

- ✅ ルールの5つの必須要素（rule, desc, condition, output, priority）
- ✅ condition式の書き方（演算子、論理演算）
- ✅ macro/listによる再利用性の向上
- ✅ 5つの実践的なルール例
- ✅ よくある失敗パターンと対策
- ✅ トラブルシューティングの基本

### 重要ポイント

1. **conditionは具体的に**
   - 広すぎると誤検知
   - 狭すぎると見逃し

2. **outputは詳細に**
   - 調査に必要な情報をすべて含める
   - user, command, container, file など

3. **正規の動作を除外**
   - システムプロセスのホワイトリスト
   - 信頼できるイメージの除外

4. **段階的にテスト**
   - 最小条件から始める
   - 徐々に条件を追加

### 次章の予告

第5回では、実運用に耐えるルールの書き方を学びます：

- 複雑なconditionの組み立て方
- コンテキスト情報の活用
- パフォーマンスチューニング
- ルールのメンテナンス戦略
- 実際の攻撃シナリオへの対応

---

## 参考資料

### 公式ドキュメント
- [Falco Rules Documentation](https://falco.org/docs/rules/)
- [Falco Rules Repository](https://github.com/falcosecurity/rules)
- [Falco Supported Fields](https://falco.org/docs/rules/supported-fields/)

### ルール例
- [Default Falco Rules](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
- [Falco Rules Explorer](https://thomas.labarussias.fr/falco-rules-explorer/)

### コミュニティ
- [Falco Slack - #falco-rules](https://kubernetes.slack.com/messages/falco)
- [Falco GitHub Discussions](https://github.com/falcosecurity/falco/discussions)

---

**所要時間**: 30分
**難易度**: ⭐⭐⭐ 中級
**前提知識**: 第3回の内容、YAML基礎

次章では、これらの基礎を応用して、本番環境で使える高度なルールを書く方法を学びます。
