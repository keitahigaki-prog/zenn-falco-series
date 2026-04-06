---
title: "付録C: 例外パターン集"
---

# 付録C: 例外パターン集

第6章で扱った「削らずに狭める」思想を、実務で頻出するパターンとしてカタログ化したものです。コピーして使う前に、必ず自環境のフィールド値を確認してください。

## C.1 CI ランナーのパッケージインストール

```yaml
exceptions:
  - name: ci_runner_package_install
    # EXPIRES: YYYY-MM-DD / OWNER: <team>
    fields: [container.image.repository, proc.pname, proc.name]
    comps: [=, =, in]
    values:
      - [<image-repo>, <entrypoint>, (apt, apt-get, dpkg, yum, dnf, rpm)]
```

## C.2 言語ランタイムの `/tmp` 実行

```yaml
exceptions:
  - name: runtime_tmp_exec
    fields: [proc.pname, proc.exepath, container.image.repository]
    comps: [in, startswith, in]
    values:
      - [(python3, node, java), /tmp/, (<image-a>, <image-b>)]
```

## C.3 kubelet / containerd 系の既定挙動

```yaml
exceptions:
  - name: container_runtime_known
    fields: [proc.name, proc.pname]
    comps: [in, in]
    values:
      - [(crictl, runc, containerd-shim), (kubelet, containerd)]
```

## 共通ルール

- すべての例外に `EXPIRES` / `OWNER` / `REASON` をコメントで残す
- namespace 単位の例外は原則使わない（使うならインシデント対応の時限のみ）
- 例外を足す PR には、想定する攻撃パターンがこの例外を通らないことの説明を書く

本書では、さらに多くの実践的な例外パターンを掲載しています。
