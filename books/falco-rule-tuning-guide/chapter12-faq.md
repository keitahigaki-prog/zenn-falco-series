---
title: "第12章 FAQ と KB・コミュニティ誘導"
---

# 第12章 FAQ と KB・コミュニティ誘導

## はじめに

Falco ルールチューニングを運用していると、必ず同じ質問に何度も遭遇します。本章では、実運用で最頻出の質問 20 項目に答え、さらにはコミュニティ・外部リソースへの誘導を解説します。

---

## よくある質問トップ20（Q&A）

### Q1: ルールが効かない・発火しない

**Q: 「このルールを有効にしたのに、予想したアラートが来ません」**

A: 以下をチェックしてください：

1. **ルール自体が有効か**
   ```bash
   falco -L | grep "rule-name"
   # enable: yes か no か確認
   ```

2. **ルールの条件を本当に満たしているか**（最頻出の原因）
   ```yaml
   - rule: Suspicious process
     condition: >
       spawned_process and
       container and
       not user_name in (allowed_users)
   ```
   上記の場合、「container 内で、かつ spawned_process」という AND 条件です。host から実行されたプロセスはマッチしません。

3. **ドライバが events をキャプチャしているか**
   ```bash
   falco -o file_output.filename=/tmp/out.txt
   # ログを 10 秒キャプチャして、event 数を確認
   ```

本章では、実運用で最頻出の20の質問とその回答を、詳しい背景説明とともに掲載しています。
