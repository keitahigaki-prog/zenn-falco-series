---
title: "第5章 マクロとリストで読みやすくする"
---

# 第5章 マクロとリストで読みやすくする

Falcoルールが複雑になると、conditionが非常に長くなり、保守が困難になります。本章では、その複雑さを管理するための重要な機能——マクロとリストの使い方について学びます。

## 5.1 マクロとは何か

マクロは、条件式（condition）の断片を名前付けして再利用する仕組みです。プログラミング言語のC言語プリプロセッサマクロに似ていますが、Falcoではフィルタリング条件に特化しています。

```yaml
- macro: shell_invocation
  condition: >
    (evt.type = execve and proc.name in (sh, bash, zsh)) or
    (evt.type = execve and proc.args contains "bash -i")
```

マクロを定義することで、このconditionのブロックを何度でも参照できるようになります。

```yaml
- rule: Suspicious shell activity
  condition: >
    shell_invocation and fd.type = file and fd.filename = /etc/passwd
  output: >
    Suspicious shell invocation (user=%user.name command=%proc.cmdline)
```

## 5.2 リストとは何か

リストは、特定の値を列挙して名前付けする機能です。複数の値を集合として管理でき、`in`演算子で値が含まれているかを判定します。

```yaml
- list: shell_binaries
  items: [sh, bash, zsh, ksh, ash]

- list: dangerous_paths
  items: [/etc/passwd, /etc/shadow, /root/.ssh, /proc/sysrq-trigger]
```

リストは値の集合を管理することに特化しているため、判定ロジックを含みません。

本書では、マクロとリストの使い分けから、複雑な条件のリファクタリング方法まで、実践的なテクニックを詳しく解説しています。
