---
title: "第2回：Falcoの基本動作を理解する（Syscalls × Rules）"
---

# Falcoの基本動作を理解する（Syscalls × Rules）

第1回では、FalcoがWireshark創設者によって生み出された、カーネルレベルのランタイムセキュリティツールであることを学びました。

しかし、「カーネルレベルで監視する」とは具体的にどういうことなのでしょうか？この章では、Falcoの内部アーキテクチャを深掘りし、システムコールの監視がどのように実装されているかを理解します。

## この章で学ぶこと

- Syscallベースのアーキテクチャ
- カーネルモジュール vs eBPFの違い
- 主要検知例（execve, chmod, mount）
- Event Sourceの種類（syscall / k8s audit / plugin）

---

## Syscallベースのアーキテクチャ

### システムコール（Syscall）とは

Linuxでは、すべてのプログラムがカーネルを経由してハードウェアにアクセスします。アプリケーションが直接ハードウェアを操作することはできず、**システムコール（syscall）**というAPIを通じてカーネルに依頼します。

```
┌─────────────────────────────────────┐
│   アプリケーション (User Space)      │
│   例: bash, curl, kubectl            │
└─────────────┬───────────────────────┘
              │ システムコール
              │ 例: open(), read(), execve()
              ▼
┌─────────────────────────────────────┐
│   Linuxカーネル (Kernel Space)      │
│   - ファイルシステム                │
│   - ネットワークスタック            │
│   - プロセス管理                    │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│   ハードウェア                      │
│   - ディスク, NIC, CPU              │
└─────────────────────────────────────┘
```

例えば、`cat /etc/passwd` というコマンドを実行すると、内部では以下のシステムコールが発行されます：

1. `execve()` - catプログラムを実行
2. `open()` - /etc/passwdファイルを開く
3. `read()` - ファイル内容を読み取る
4. `write()` - 標準出力に書き出す
5. `close()` - ファイルを閉じる

**Falcoはこれらのシステムコールをすべて監視**します。

### Falcoのデータフロー

Falcoがシステムコールをどのように検知し、アラートを生成するかの全体像：

```
┌─────────────────────────────────────────────────────┐
│  1. アプリケーション層                               │
│     $ kubectl exec pod -- bash                       │
│     $ cat /etc/shadow                                │
└─────────────┬───────────────────────────────────────┘
              │ システムコール
              │ execve("/bin/bash")
              │ open("/etc/shadow", O_RDONLY)
              ▼
┌─────────────────────────────────────────────────────┐
│  2. Linuxカーネル                                    │
│     ┌─────────────────────────────────────┐         │
│     │ Falco Driver (カーネル内部)        │         │
│     │ ・カーネルモジュール または         │         │
│     │ ・eBPFプログラム                    │         │
│     │                                     │         │
│     │ → syscallをフック                  │         │
│     │ → イベント情報を収集               │         │
│     └─────────────┬───────────────────────┘         │
└───────────────────┼─────────────────────────────────┘
                    │ リングバッファ経由
                    │ イベントストリーム
                    ▼
┌─────────────────────────────────────────────────────┐
│  3. Falco (User Space)                              │
│     ┌─────────────────────────────────────┐         │
│     │ libsinsp/libscap                    │         │
│     │ → イベントをパース                 │         │
│     │ → コンテキスト情報を付与           │         │
│     └─────────────┬───────────────────────┘         │
│                   │                                 │
│     ┌─────────────▼───────────────────────┐         │
│     │ Falco Rule Engine                   │         │
│     │ → ルールとマッチング               │         │
│     │ → フィルタリング                   │         │
│     └─────────────┬───────────────────────┘         │
│                   │ マッチしたら                   │
│     ┌─────────────▼───────────────────────┐         │
│     │ Output                              │         │
│     │ → JSON/テキスト形式でアラート      │         │
│     │ → ファイル/stdout/gRPC              │         │
│     └─────────────────────────────────────┘         │
└─────────────────────────────────────────────────────┘
```

**重要なポイント**：
- カーネル内部でイベントを収集（改ざん不可能）
- User Spaceで柔軟なルール処理
- パフォーマンスとセキュリティのバランス

### なぜシステムコールを監視するのか

すべての攻撃は、最終的にシステムコールを通じて実行されます：

| 攻撃手法 | 使用されるシステムコール |
|---------|------------------------|
| ファイル読み取り | `open()`, `read()` |
| プロセス実行 | `execve()`, `fork()` |
| ネットワーク通信 | `socket()`, `connect()`, `sendto()` |
| 権限変更 | `chmod()`, `chown()`, `setuid()` |
| ファイルシステム操作 | `mount()`, `unlink()`, `rename()` |

攻撃者がどんな高度な手法を使っても、**システムコールを回避することはできません**。これが、Falcoのアプローチが強力な理由です。

---

## カーネルモジュール vs eBPF

Falcoには2つのドライバー実装があります。どちらもシステムコールを監視しますが、仕組みが異なります。

### カーネルモジュール方式

**仕組み**:
- Linuxカーネルに動的にロードされるモジュール（`.ko`ファイル）
- カーネルのsyscallテーブルをフックして、すべてのsyscallをインターセプト

**メリット**:
- ✅ **パフォーマンスが高い** - カーネル内で直接動作
- ✅ **すべてのsyscallをキャプチャ** - 漏れがない
- ✅ **成熟した実装** - 長年の実績

**デメリット**:
- ❌ **カーネルバージョンに依存** - カーネル更新時に再ビルドが必要
- ❌ **セキュリティリスク** - カーネルモジュールのバグはカーネルクラッシュに直結
- ❌ **一部環境で使えない** - GKE Autopilot、AWS Fargate、一部のマネージドK8sで非対応

**インストール方法**:
```bash
# カーネルヘッダーが必要
apt-get install linux-headers-$(uname -r)

# Falcoが自動でモジュールをビルド＆ロード
systemctl start falco
```

**確認**:
```bash
lsmod | grep falco
# 出力例: falco  163840  0
```

### eBPF方式

**仕組み**:
- Extended Berkeley Packet Filter（eBPF）を使用
- カーネル内部でサンドボックス化されたBPFプログラムを実行
- syscallをトレースポイントでフック

**メリット**:
- ✅ **安全** - BPFバリデーターがプログラムを検証、カーネルクラッシュを防止
- ✅ **カーネルバージョンに依存しにくい** - BTF（BPF Type Format）対応カーネルなら再ビルド不要
- ✅ **マネージドK8sで動作** - GKE、EKSで公式サポート

**デメリット**:
- ❌ **若干のオーバーヘッド** - BPFバリデーションと安全性チェックのコスト
- ❌ **カーネル要件** - Linux 4.14以降（推奨は5.8以降）
- ❌ **一部機能に制限** - BPFの制約内でしか動作できない

**インストール方法**:
```bash
# eBPFドライバーを指定して起動
falco --modern-bpf
# または
FALCO_BPF_PROBE="" falco
```

**確認**:
```bash
bpftool prog list | grep falco
# 出力例: 123: tracing  name falco_probe  ...
```

### どちらを選ぶべきか

| 環境 | 推奨 | 理由 |
|------|------|------|
| **本番環境（自己管理クラスタ）** | eBPF | 安全性が高く、カーネル更新に強い |
| **本番環境（マネージドK8s）** | eBPF | GKE/EKS/AKSで必須 |
| **検証環境** | カーネルモジュール | パフォーマンス測定に最適 |
| **古いカーネル（< 4.14）** | カーネルモジュール | eBPFが使えない |
| **AWS Fargate / GKE Autopilot** | 対応不可 | 別のセキュリティ手法を検討 |

**推奨**: 特別な理由がない限り、**eBPF方式**を選択してください。

### パフォーマンス比較

実際のパフォーマンス影響（Falco公式ベンチマーク）：

| 指標 | ドライバーなし | カーネルモジュール | eBPF |
|------|---------------|-------------------|------|
| CPU使用率 | 基準 | +2-5% | +3-7% |
| メモリ使用量 | 基準 | +50MB | +60MB |
| レイテンシ | 基準 | +0.1ms | +0.2ms |

**結論**: どちらもほぼ無視できるレベルのオーバーヘッド。本番環境で十分使用可能。

---

## 主要な検知例

実際のシステムコールとFalcoルールの対応を見ていきましょう。

### execve - プロセス実行の検知

**システムコール**: `execve(path, argv, envp)`

新しいプログラムを実行するときに呼ばれます。

**検知例**: コンテナ内でシェルが起動された

```yaml
- rule: Shell Spawned in Container
  desc: コンテナ内で対話型シェルが起動された
  condition: >
    spawned_process and
    container and
    proc.name in (bash, sh, zsh, fish, csh, tcsh, dash) and
    not proc.pname in (node, python, java)
  output: >
    Shell spawned in container
    (user=%user.name container=%container.name
     shell=%proc.name parent=%proc.pname
     cmdline=%proc.cmdline)
  priority: WARNING
```

**実際のイベント**:
```json
{
  "evt.type": "execve",
  "evt.args": "/bin/bash",
  "proc.name": "bash",
  "proc.pname": "kubectl",
  "container.name": "nginx-pod",
  "user.name": "root"
}
```

**なぜ検知されるか**:
1. `kubectl exec` がコンテナ内で `/bin/bash` を実行
2. カーネルが `execve("/bin/bash", ...)` を呼び出し
3. Falcoドライバーがこれをキャプチャ
4. ルールエンジンが `proc.name=bash` かつ `container=true` にマッチ
5. アラート生成

### chmod - 権限変更の検知

**システムコール**: `chmod(path, mode)`

ファイルの権限ビットを変更します。

**検知例**: SUIDビットが設定された

```yaml
- rule: Set Setuid or Setgid bit
  desc: SUIDまたはSGIDビットが設定された（権限昇格のリスク）
  condition: >
    chmod and
    (evt.arg.mode contains "S_ISUID" or
     evt.arg.mode contains "S_ISGID") and
    not proc.name in (dpkg, rpm, apt, yum)
  output: >
    SUID/SGID bit set
    (user=%user.name file=%evt.arg.filename
     mode=%evt.arg.mode command=%proc.cmdline)
  priority: CRITICAL
```

**攻撃シナリオ**:
```bash
# 攻撃者がSUIDビットを設定
chmod +s /tmp/evil-binary

# これにより、一般ユーザーでもroot権限で実行可能に
ls -l /tmp/evil-binary
# -rwsr-xr-x 1 attacker attacker 12345 Dec 1 10:00 /tmp/evil-binary
```

**Falcoが検知するsyscall**:
```c
chmod("/tmp/evil-binary", 04755)  // 04xxx = SUID bit
```

### mount - ファイルシステム操作の検知

**システムコール**: `mount(source, target, fstype, flags, data)`

ファイルシステムをマウントします。Container Escapeでよく使われます。

**検知例**: 特権コンテナでホストのファイルシステムをマウント

```yaml
- rule: Mount Launched in Privileged Container
  desc: 特権コンテナ内でmountコマンドが実行された
  condition: >
    evt.type = mount and
    container and
    container.privileged = true and
    not proc.name in (systemd, snapd)
  output: >
    Mount in privileged container
    (user=%user.name container=%container.name
     source=%evt.arg.source target=%evt.arg.target
     fstype=%evt.arg.fstype)
  priority: CRITICAL
```

**Container Escape攻撃例**:
```bash
# 特権コンテナ内で
docker run --privileged -it alpine sh

# ホストのルートファイルシステムをマウント
mkdir /host
mount /dev/sda1 /host

# ホストのファイルにアクセス可能に！
ls /host
cat /host/etc/shadow
```

**Falcoが検知するsyscall**:
```c
mount("/dev/sda1", "/host", "ext4", MS_RDONLY, NULL)
```

---

## Event Sourceの種類

Falcoは、システムコールだけでなく、複数のイベントソースに対応しています。

### Syscall Events

これまで説明してきたシステムコールベースのイベント。

**特徴**:
- **最も低レイヤー** - すべての動作をキャプチャ
- **改ざん不可能** - カーネルレベルの監視
- **詳細な情報** - プロセス、ファイル、ネットワークすべて

**使用例**:
- プロセス実行の監視
- ファイルアクセスの監視
- ネットワーク通信の監視

### Kubernetes Audit Events（Plugin）

KubernetesのAPIサーバーに対する操作を監視。

**特徴**:
- **API操作を監視** - kubectl、CI/CD、Operatorの操作
- **システムコールでは見えない情報** - RoleBindingの変更、Secretの取得など
- **k8s auditプラグインで実装** - Falco 0.32以降

**イベント例**:
```json
{
  "verb": "create",
  "objectRef": {
    "resource": "rolebindings",
    "name": "admin-binding",
    "namespace": "default"
  },
  "user": {
    "username": "attacker@example.com"
  }
}
```

**検知ルール例**:
```yaml
- rule: Attach to Privileged Pod
  desc: 特権Podへkubectl execが実行された
  condition: >
    ka.verb = "create" and
    ka.target.resource = "pods/exec" and
    ka.target.pod.privileged = true
  output: >
    Attach to privileged pod
    (user=%ka.user.name pod=%ka.target.name
     namespace=%ka.target.namespace)
  priority: WARNING
  source: k8s_audit
```

**設定方法** (第7回で詳しく解説):
```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  verbs: ["create", "update", "delete", "patch"]
```

### Cloud Events（Plugin）

クラウドプロバイダーのイベントを監視。

**対応プラグイン**:
- **CloudTrail** - AWSのAPI操作
- **Cloud Audit Logs** - GCPのAPI操作
- **Okta** - 認証・認可イベント
- **GitHub** - リポジトリへのアクセス

**例: CloudTrailイベント**:
```yaml
- rule: S3 Bucket Made Public
  desc: S3バケットが公開設定にされた
  condition: >
    ct.name = "PutBucketAcl" and
    ct.request.acl contains "PublicRead"
  output: >
    S3 bucket made public
    (user=%ct.user bucket=%ct.request.bucket)
  priority: CRITICAL
  source: aws_cloudtrail
```

### Event Sourceの組み合わせ

複数のEvent Sourceを組み合わせることで、**攻撃チェーン全体を追跡**できます。

**例: クロスソース相関**

```
1. [K8s Audit] kubectl execでPodに侵入
   ↓
2. [Syscall] Podから認証情報ファイルを読み取り
   ↓
3. [CloudTrail] 盗んだ認証情報でS3にアクセス
   ↓
4. [Syscall] データを外部に送信
```

このような攻撃チェーンを、Falcoの複数Event Sourceで検知・追跡できます。

---

## まとめ

この章では、Falcoの内部アーキテクチャを学びました：

- **Syscallベース**: すべての動作はシステムコールを通じて行われる
- **2つのドライバー**: カーネルモジュール（高速）vs eBPF（安全）
- **主要検知**: execve、chmod、mountなどのsyscallを監視
- **複数のEvent Source**: syscall、k8s audit、cloudプラグインを組み合わせ

次章では、実際にローカル環境でFalcoを動かし、システムコールの検知を体験します。

---

## 参考資料

- [Falco Architecture Documentation](https://falco.org/docs/architecture/)
- [eBPF Documentation](https://ebpf.io/)
- [Linux System Call Table](https://filippo.io/linux-syscall-table/)
- [Falco Drivers Comparison](https://falco.org/docs/event-sources/drivers/)
- [Kubernetes Audit Logs](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
