---
title: "第3回：ローカル環境でFalcoを動かす（最速10分Hands-on）"
---

# ローカル環境でFalcoを動かす（最速10分Hands-on）

第1回・第2回で学んだFalcoの理論を、実際に手を動かして体験しましょう。この章では、わずか10分でFalcoをローカル環境にセットアップし、実際の脅威検知を体験できます。

## この章で学ぶこと

- [OK] ローカル環境でのFalco環境構築（3つの方法）
- [OK] Falcoのインストールと起動
- [OK] 実際の脅威検知を体験
- [OK] デバッグとトラブルシューティング

---

## 前提条件

以下のいずれかの環境が準備されていることを確認してください：

### 推奨環境

| 環境 | 難易度 | セットアップ時間 | 推奨度 |
|------|--------|-----------------|--------|
| **Docker Desktop** | ★ 簡単 | 5分 | ★★★ 最推奨 |
| **Kind** | ★★ 普通 | 10分 | ★★ 推奨 |
| **Minikube** | ★★ 普通 | 10分 | ★★ 推奨 |
| **実マシン** | ★★★ 難しい | 15分 | ★ 非推奨 |

### システム要件

- **OS**: macOS, Linux, Windows（WSL2）
- **メモリ**: 最低4GB（8GB推奨）
- **CPU**: 2コア以上
- **ディスク**: 10GB以上の空き容量

:::message
**この章の方針**
最も簡単で誰でも試せる**Docker Desktop**を使った方法をメインに解説します。Kind/Minikubeの方法も最後に補足します。
:::

---

## 方法1: Docker Desktop + Falco（最推奨）

### ステップ1: Docker Desktopの準備

まず、Docker Desktopがインストールされているか確認します：

```bash
# Dockerのバージョン確認
docker --version
# 期待される出力: Docker version 25.0.0 以降

# Dockerが動作しているか確認
docker ps
```

もしDockerがインストールされていない場合：

```bash
# macOS（Homebrew）
brew install --cask docker

# または公式サイトからダウンロード
# https://www.docker.com/products/docker-desktop/
```

### ステップ2: Falcoコンテナを起動

Falcoを最も簡単に動かす方法は、公式のDockerイメージを使用することです：

```bash
# Falcoコンテナを起動（ホストのファイルシステムを監視）
docker run --rm -i -t \
  --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /dev:/host/dev \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  -v /etc:/host/etc:ro \
  falcosecurity/falco:latest
```

**オプションの説明:**

| オプション | 説明 |
|-----------|------|
| `--privileged` | カーネルモジュールへのアクセス許可 |
| `-v /var/run/docker.sock` | Docker APIへのアクセス |
| `-v /dev` | デバイスファイルへのアクセス |
| `-v /proc` | プロセス情報の監視 |
| `-v /boot` | カーネルヘッダーへのアクセス |
| `-v /lib/modules` | カーネルモジュールのロード |

### ステップ3: Falcoが起動したことを確認

Falcoコンテナを起動すると、以下のような出力が表示されます：

```text
Mon Nov 25 15:00:00 2025: Falco version: 0.37.0
Mon Nov 25 15:00:00 2025: Falco initialized with configuration file: /etc/falco/falco.yaml
Mon Nov 25 15:00:00 2025: Loading rules from file /etc/falco/falco_rules.yaml
Mon Nov 25 15:00:00 2025: Loading rules from file /etc/falco/falco_rules.local.yaml
Mon Nov 25 15:00:00 2025: The chosen syscall buffer dimension is: 8388608 bytes
Mon Nov 25 15:00:00 2025: Starting health webserver with threadiness 2, listening on 0.0.0.0:8765
Mon Nov 25 15:00:00 2025: Loaded event sources: syscall
Mon Nov 25 15:00:00 2025: Enabled event sources: syscall
Mon Nov 25 15:00:00 2025: Opening 'syscall' source with modern BPF probe.
```

[OK] **"Opening 'syscall' source"** が表示されていれば成功です！

---

## ハンズオン：実際に脅威を検知してみる

Falcoが起動したら、実際に脅威行動をシミュレートして検知を体験しましょう。

### 実験1: センシティブファイルへの書き込み

**別のターミナル**を開いて、以下を実行します：

```bash
# Alpine Linuxコンテナを起動
docker run --rm -it alpine sh
```

コンテナ内で、センシティブファイル（`/etc/shadow`）に触れてみます：

```bash
# コンテナ内で実行
touch /etc/shadow
```

**Falcoの出力を確認:**

Falcoが動いているターミナルに戻ると、以下のようなアラートが表示されているはずです：

```text
15:01:23.123456789: Warning Write below etc (user=root user_loginuid=-1 command=touch /etc/shadow pid=12345 file=/etc/shadow parent=sh container_id=abc123 container_name=confident_darwin)
```

 **おめでとうございます！** これがFalcoによる脅威検知です。

**アラートの読み方:**

| 項目 | 説明 |
|------|------|
| `15:01:23.123456789` | タイムスタンプ（ナノ秒精度） |
| `Warning` | 深刻度レベル |
| `Write below etc` | ルール名 |
| `user=root` | 実行ユーザー |
| `command=touch /etc/shadow` | 実行されたコマンド |
| `pid=12345` | プロセスID |
| `file=/etc/shadow` | 対象ファイル |
| `container_id=abc123` | コンテナID |

### 実験2: シェルの起動検知

次に、コンテナ内でシェルを起動してみます：

```bash
# コンテナ内で実行
sh
exit  # 終了
```

**Falcoの出力:**

```text
15:02:15.123456789: Notice A shell was spawned in a container with an attached terminal (user=root user_loginuid=-1 k8s_ns=<NA> k8s_pod=<NA> container=abc123 shell=sh parent=sh cmdline=sh terminal=34816 container_id=abc123 image=alpine)
```

### 実験3: パッケージ管理ツールの実行

```bash
# コンテナ内で実行
apk update
```

**Falcoの出力:**

```text
15:03:45.123456789: Error Package management process launched in container (user=root user_loginuid=-1 command=apk update pid=12346 container_id=abc123 container_name=confident_darwin image=alpine:latest)
```

### 実験4: 特権昇格の試行

```bash
# コンテナ内で実行
sudo su -
# （sudoがインストールされていない場合、警告は出ませんが、実際の環境では検知されます）
```

---

## より詳細な検証：カスタムルールで遊ぶ

基本的な検知が動作したら、次はカスタムルールを試してみましょう。

### カスタムルールファイルの作成

ローカルに簡単なルールファイルを作成します：

```bash
# custom_rules.yaml を作成
cat > custom_rules.yaml <<'EOF'
- rule: Detect cat on sensitive files
  desc: Detect if someone is reading sensitive files with cat
  condition: >
    spawned_process and
    proc.name = cat and
    (fd.name startswith /etc/passwd or
     fd.name startswith /etc/shadow)
  output: >
    Sensitive file read
    (user=%user.name command=%proc.cmdline file=%fd.name
     container_id=%container.id container_name=%container.name)
  priority: WARNING
  tags: [filesystem, security]
EOF
```

### カスタムルールでFalcoを起動

```bash
# カスタムルールファイルをマウントして起動
docker run --rm -i -t \
  --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /dev:/host/dev \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  -v /etc:/host/etc:ro \
  -v $(pwd)/custom_rules.yaml:/etc/falco/rules.d/custom_rules.yaml \
  falcosecurity/falco:latest
```

### カスタムルールをテスト

```bash
# 別ターミナルでAlpineコンテナを起動
docker run --rm -it alpine sh

# コンテナ内で実行
cat /etc/passwd
```

**Falcoの出力:**

```text
15:10:23.123456789: Warning Sensitive file read (user=root command=cat /etc/passwd file=/etc/passwd container_id=xyz789 container_name=happy_pascal)
```

 **カスタムルールが動作しました！**

---

## 実践的なシナリオ：コンテナからの逃走を検知

より実践的なシナリオとして、コンテナからホストへの逃走（Container Escape）を試してみます。

### シナリオ：ホストのファイルシステムへのアクセス

```bash
# 特権コンテナを起動（危険な設定）
docker run --rm -it --privileged -v /:/host alpine sh

# コンテナ内からホストのファイルシステムにアクセス
ls /host/root/
cat /host/etc/shadow
```

**Falcoの出力:**

```text
15:15:00.123456789: Critical Container with sensitive mount (container_id=def456 mount_source=/ mount_dest=/host image=alpine:latest)
15:15:05.123456789: Warning Read sensitive file untrusted (user=root file=/host/etc/shadow)
```

:::message alert
**注意**
このような特権コンテナの起動は、本番環境では絶対に避けるべきです。これは学習目的の実験です。
:::

---

## デバッグとトラブルシューティング

### 問題1: Falcoが起動しない

**症状:**
```text
ERROR: Could not open /host/proc
```

**解決方法:**
- `/proc`マウントが正しいか確認
- `--privileged`フラグが付いているか確認

```bash
# 正しいコマンドの例
docker run --rm -i -t --privileged \
  -v /proc:/host/proc:ro \
  falcosecurity/falco:latest
```

### 問題2: アラートが全く表示されない

**症状:**
Falcoは起動しているが、何をしてもアラートが出ない

**原因と解決:**

1. **ルールファイルが読み込まれていない**
   ```bash
   # ログを確認
   docker logs <falco-container-id>
   # "Loading rules from file" が表示されているか確認
   ```

2. **カーネルモジュールが読み込めていない**
   ```bash
   # eBPF probeが使われているか確認
   # ログに "Opening 'syscall' source with modern BPF probe" があるか
   ```

### 問題3: パーミッションエラー

**症状:**
```text
ERROR: Cannot load kernel module
```

**解決方法（macOS特有）:**

macOSではLinuxカーネルモジュールを直接使用できないため、DockerのLinux VM内でFalcoを動かす必要があります：

```bash
# macOSの場合、必ずDocker Desktop経由で実行
docker run --rm -i -t \
  --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  falcosecurity/falco:latest
```

### 問題4: ログが多すぎる

**症状:**
大量のアラートが表示され、重要なものが埋もれる

**解決方法:**

1. **フィルタリング**
   ```bash
   # WARNINGレベル以上のみ表示
   docker logs <container-id> 2>&1 | grep -E "Warning|Error|Critical"
   ```

2. **ルールの無効化**
   ```yaml
   # /etc/falco/falco_rules.local.yaml
   - rule: Terminal shell in container
     enabled: false  # このルールを無効化
   ```

---

## 方法2: Kind（Kubernetes in Docker）

Kubernetesクラスター内でFalcoを試したい場合は、Kindを使用します。

### Kindのインストール

```bash
# macOS
brew install kind

# Linux
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.30.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
```

### Kindクラスターの作成

```bash
# クラスター作成
kind create cluster --name falco-test

# 確認
kubectl cluster-info --context kind-falco-test
```

### FalcoをHelmでインストール

```bash
# Helmリポジトリを追加
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Falcoをインストール
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set falco.grpc.enabled=true \
  --set falco.grpc_output.enabled=true
```

### 動作確認

```bash
# Falco Podの確認
kubectl get pods -n falco

# ログを確認
kubectl logs -n falco -l app.kubernetes.io/name=falco -f
```

### テスト用Podで脅威をシミュレート

```bash
# テストPodを作成
kubectl run test-pod --image=alpine --restart=Never -- sleep 3600

# Podに入る
kubectl exec -it test-pod -- sh

# 脅威行動を実行
touch /etc/shadow
```

**Falcoのログで検知を確認:**

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "Write below etc"
```

---

## 方法3: Minikube

### Minikubeのインストール

```bash
# macOS
brew install minikube

# Linux
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
```

### Minikubeクラスターの起動

```bash
minikube start --driver=docker --cpus=2 --memory=4096
```

### Falcoのインストール（Kind と同じ）

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace
```

---

## ログの高度な活用

### JSONフォーマットで出力

Falcoのログを構造化データとして扱いたい場合：

```yaml
# falco.yaml の設定
json_output: true
json_include_output_property: true
```

**出力例:**

```json
{
  "output": "15:20:00.123456789: Warning Write below etc (user=root...)",
  "priority": "Warning",
  "rule": "Write below etc",
  "time": "2025-11-25T15:20:00.123456789Z",
  "output_fields": {
    "container.id": "abc123",
    "evt.time": "15:20:00.123456789",
    "fd.name": "/etc/shadow",
    "proc.name": "touch",
    "user.name": "root"
  }
}
```

### ログをファイルに保存

```bash
# Falcoコンテナ起動時にログをファイルに出力
docker run --rm -i -t \
  --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v $(pwd)/falco-logs:/var/log/falco \
  falcosecurity/falco:latest \
  -o file_output.enabled=true \
  -o file_output.filename=/var/log/falco/events.log
```

---

## 次のステップ

この章では、Falcoをローカル環境で動かし、実際の脅威検知を体験しました。

### 学んだこと

- [OK] Docker Desktop/Kind/MinikubeでのFalco環境構築
- [OK] Falcoの起動と基本操作
- [OK] センシティブファイルへのアクセス検知
- [OK] シェル起動、パッケージ管理ツールの検知
- [OK] カスタムルールの作成と適用
- [OK] トラブルシューティング

### 次章の予告

第4回では、Falcoのルールを自分で書く方法を学びます：

- Falcoルールの基本構文
- conditionの書き方
- outputのカスタマイズ
- priorityとtagsの使い分け
- 実践的なルール例

---

## 演習問題

手を動かして理解を深めましょう：

### 演習1: 基本的な検知

以下の操作を行い、Falcoがどのようなアラートを出すか確認してください：

```bash
# コンテナ内でviを起動
vi /tmp/test.txt

# コンテナ内でcurlを実行
curl https://example.com

# コンテナ内でネットワーク情報を確認
netstat -an
```

### 演習2: カスタムルールの作成

以下の条件を検知するカスタムルールを作成してください：

- `/tmp`ディレクトリ以外へのファイル作成
- `wget`または`curl`の実行
- 環境変数`PATH`の変更

### 演習3: 複数コンテナでの検証

複数のコンテナを起動し、それぞれで異なる脅威行動をシミュレートしてください。Falcoがコンテナを区別して検知できることを確認してください。

---

## 参考資料

### 公式ドキュメント
- [Falco Installation Guide](https://falco.org/docs/getting-started/installation/)
- [Falco Docker Image](https://hub.docker.com/r/falcosecurity/falco)
- [Falco Configuration](https://falco.org/docs/configuration/)

### コミュニティリソース
- [Falco GitHub](https://github.com/falcosecurity/falco)
- [Falco Slack](https://kubernetes.slack.com/messages/falco)
- [Falco Examples](https://github.com/falcosecurity/falco/tree/master/examples)

### 関連ツール
- [Kind](https://kind.sigs.k8s.io/)
- [Minikube](https://minikube.sigs.k8s.io/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/)

---

**所要時間**: 15分（初回は20-30分）
**難易度**: ★★ 初中級
**前提知識**: Docker基本操作

次章では、これらの検知を生み出す「Falcoルール」の書き方を詳しく学びます。
