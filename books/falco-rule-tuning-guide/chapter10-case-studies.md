---
title: "第10章 実戦ケーススタディ"
---

# 第10章 実戦ケーススタディ

本章は、Falcoの運用経験から抽出された8つのリアルな例を扱います。各ケーススタディは「何が起きたか → 何がノイズだったか → 何がノイズではなかったか → どう調べたか → どうチューニングしたか」という流れで解説されます。

---

## ケース1: curl | bash — ビルドスクリプト内のインストーラ実行

### 状況

製品X社のSREチームは、オンボーディングスクリプト内で以下を実行していました。

```bash
#!/bin/bash
# App version upgrade install script
curl -fsSL https://releases.example.com/install.sh | bash -s -- --version=1.2.3
```

このスクリプトがコンテナ内で実行されるたびに、Falcoが検知していました。

### Falcoからのアラート出力

```
2026-04-06T09:15:23.456Z CRITICAL Rule: Execution from /tmp
  evt.type=execve user.uid=1000
  container.id=abc123def456
  container.image=company/installer:1.0
  proc.name=bash
  proc.exepath=/bin/bash
  proc.args=-s -- --version=1.2.3
  fd.name=<stdin>
  ka.pod.name=upgrade-job-2026-04-06-12345
  ka.namespace.name=ops

2026-04-06T09:15:24.123Z WARNING Rule: Suspicious Binary
  proc.name=sh
  proc.exepath=/bin/sh
  container.image=company/installer:1.0
  ka.pod.name=upgrade-job-2026-04-06-12345
```

本章では、この他7つのケーススタディを含め、それぞれの調査プロセスと最終的なチューニング方法を詳しく解説しています。
