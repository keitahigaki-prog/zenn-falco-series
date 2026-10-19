---
title: "第9章 チューニングの回帰テスト ― 削った先に攻撃が通っていないか"
---

# 第9章 チューニングの回帰テスト ― 削った先に攻撃が通っていないか

第6章で、7種類の正常業務ワークロードに対する例外・override設計を行い、アラート件数を15件から2件まで減らしました。しかし、**チューニングが成功したかどうかは「アラートが減ったこと」では判定できません。** 消しすぎて検知が効かなくなっていないか（ザル化）を確かめるには、実際に攻撃を仕掛けて、それでも検知されることを確認するしかありません。

本章では、姉妹本『攻撃して学ぶKubernetes Runtime Security』のラボで検証済みの攻撃手順を、チューニング後のtuning-labに対してそのまま再生します。これを**回帰テスト**と呼びます。

## 9.1 なぜユニットテストではなく「攻撃の再生」なのか

ルールのconditionを単体でテストすることは可能です（`falco -V`で構文は検証できますし、第10章でCIに組み込みます）。しかし構文が正しくても、「このルールが本当に守りたい攻撃経路を検知できるか」は別の問題です。例外を1個足すたびに、「この例外は攻撃者が再現できる条件まで含んでいないか」を人間が吟味するのは現実的ではありません。

そこで、**チューニング前に検知できていた攻撃シナリオの集合を固定し、チューニングのたびに全部再生して、検知結果に差分がないかを機械的に見る**というアプローチを取ります。すでに動く攻撃ラボ（姉妹本）があるなら、そこで実証済みのシナリオをそのまま流用するのが最も手早い方法です。

## 9.2 回帰セットを用意する

tuning-labに、姉妹本のラボで使った攻撃対象をそのままデプロイします（`lab/manifests/01-vulnerable-webapp.yaml`、`05-attacker-listener.yaml`、`07-misconfigured-pod.yaml`）。tuning-labは単一ノード構成のため、`lab-role=victim`ラベルをノードに付与する必要がありました。

```bash
kubectl label node tuning-lab-control-plane lab-role=victim --overwrite
kubectl apply -f lab/manifests/00-namespace.yaml -f lab/manifests/01-vulnerable-webapp.yaml
kubectl apply -f lab/manifests/05-attacker-listener.yaml -f lab/manifests/07-misconfigured-pod.yaml
```

今回は、姉妹本の実測で性質が異なる3つの攻撃を回帰セットとして選びました。

| 回帰テストID | 元ネタ | 攻撃の性質 |
|---|---|---|
| R1 | Lab 1 | Webアプリの脆弱性（コマンドインジェクション）経由、TTYなしのプログラム的侵入 |
| R2 | Lab 7 | 特権コンテナ・hostPath悪用による`/etc/shadow`読み取り |
| R3 | Lab 9 | Linux Capabilities（`CAP_SYS_PTRACE`）悪用 |

## 9.3 再生する

### R1: コマンドインジェクション

```bash
kubectl -n lab run attacker --rm -i --image=curlimages/curl --restart=Never -- \
  curl -s "http://vulnerable-webapp.lab.svc/ping?host=127.0.0.1;id"
```

### R2: 特権コンテナ経由の `/etc/shadow` 読み取り

```bash
kubectl -n lab exec misconfigured-pod -- sh -c "chroot /host cat /etc/shadow | head -3"
```

### R3: `CAP_SYS_PTRACE` 悪用

```bash
kubectl -n lab exec cap-abuse-pod -- sh -c "apk add --no-cache strace; strace -p 1 -f -e trace=none"
```

## 9.4 結果：3件とも検知が生きている

チューニング適用後のtuning-labで実際に再生したところ、3件とも正しく検知されました。

```json
{"rule":"Redirect STDOUT/STDIN to Network Connection in Container","output_fields":{"proc.name":"ping", ...}}
{"rule":"Read sensitive file untrusted","output_fields":{"k8s.pod.name":"misconfigured-pod","proc.name":"cat", ...}}
{"rule":"Drop and execute new binary in container","output_fields":{"k8s.pod.name":"cap-abuse-pod","proc.name":"strace", ...}}
{"rule":"PTRACE attached to process","output_fields":{"k8s.pod.name":"cap-abuse-pod","proc.name":"strace", ...}}
{"rule":"PTRACE anti-debug attempt","output_fields":{"k8s.pod.name":"cap-abuse-pod","proc.name":"strace", ...}}
```

R1が`Terminal shell in container`ではなく`Redirect STDOUT/STDIN to Network Connection in Container`で検知されているのは、第3章で説明した通り「TTYなしのプログラム的侵入は`Terminal shell in container`の対象外」だからです。ここでもし「チューニング後に攻撃検知が消えた」と誤読してしまうと、正しく機能しているルールを疑って余計な調整をしてしまいます。**第3章でconditionを読めていることが、回帰テストの結果を正しく解釈するための前提になっている**わけです。

同じ再生の間、チューニング済みの正常業務ノイズ（N1の`config-reloader`、N4の`password-expiry-audit`など）は一切再発していません。つまり今回のチューニングは、「ノイズだけを削って、攻撃経路は塞いでいない」という意味で妥当だったと判断できます。

## 9.5 回帰セットの運用

- **例外・overrideを追加・変更するたびに、回帰セットを再生する。** 最低限、変更したルールに関連する攻撃シナリオだけでも流す
- **回帰セットは「upstreamルールが変わっても意味を持つ」ものを選ぶ。** 特定バージョンの条件式に依存した攻撃手順ではなく、MITRE ATT&CKのテクニック単位で選定すると長持ちする
- **攻撃ラボと正常業務ノイズのラボは、同じクラスタで同時に動かして良い。** むしろ同時に動かすことで、「ノイズの中に攻撃を混ぜても検知が埋もれないか」まで確認できる
- **回帰セットが増えすぎたら、CIで自動化する。** 第10章で、この再生をスクリプト化してCIパイプラインに組み込む方法を扱う

## 9.6 まとめ

- アラート件数が減ったことは、チューニングの成功を意味しない。攻撃を実際に再生して検知が残っているかを確認するまでがチューニング作業
- 回帰セットは、すでに動いている攻撃ラボ（自作でも、姉妹本のようなものでも）から転用するのが最も現実的
- 回帰テストの結果を正しく読むには、第3章で扱った「どのルールがどの性質の攻撃を担当しているか」の理解が前提になる
