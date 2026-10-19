---
title: "第2章 チューニングラボを作る"
---

# 第2章 チューニングラボを作る

本書のすべての章は、実際に動かしたFalcoとKubernetesクラスタ上の実測に基づいています。本章では、そのラボをどう組んだかを説明します。手元で同じように再現すれば、本書のどの実測も自分の環境で確認できます。

## 2.1 なぜ「攻撃ラボ」だけでは足りないのか

姉妹本『攻撃して学ぶKubernetes Runtime Security』のラボは、**攻撃を再現して何が検知され、何が漏れるか**を見るためのものでした。しかし本書のテーマである「チューニング」を学ぶには、それだけでは不十分です。チューニングの本当の難しさは、攻撃ではなく **正常な業務が、意図せずupstreamルールを踏んでしまう** ところにあるからです。

そこで本書では、姉妹本と同じクラスタ構成・同じFalcoバージョンを使った**別クラスタ（tuning-lab）**を用意し、次の2つを両立させます。

1. **正常業務ワークロード**：攻撃ではないが、upstreamルールの条件に偶然マッチしてしまう7種類のワークロード（第6章で使用）
2. **姉妹本の攻撃シナリオの再生**：チューニング後も検知が生きているかを確認する回帰テスト（第9章で使用）

## 2.2 環境

検証に使ったバージョンは次の通りです（執筆時点の最新安定版に固定）。

| コンポーネント | バージョン |
|---|---|
| kind | v0.32.0 |
| Kubernetes | v1.36.1 |
| Falco | 0.45.0 |
| Helm chart (`falcosecurity/falco`) | 9.2.0 |
| ドライバ | modern_ebpf |

姉妹本のラボは3ノード（control-plane + worker×2）構成ですが、本書のラボは正常業務ワークロードを7種類動かすだけなので、**単一ノード**で十分です。

```yaml
# tuning/kind/kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: tuning-lab
nodes:
  - role: control-plane
    labels:
      lab-role: "tuning"
```

```bash
kind create cluster --config tuning/kind/kind-config.yaml
```

Falcoのインストールは姉妹本と同一のHelm chart・バージョンを使い、分析しやすいようJSON出力を有効にします。

```yaml
# tuning/falco-values.yaml
driver:
  kind: modern_ebpf
tty: true
falco:
  json_output: true
  json_include_output_property: true
  json_include_tags_property: true
```

```bash
helm install falco falcosecurity/falco --version 9.2.0 -n falco -f tuning/falco-values.yaml \
  --set-file 'customRules.tuning-rules\.yaml=tuning/rules/tuning-rules.yaml'
```

## 2.3 「踏むと想定するルール」を先にコメントしてから作る

正常業務ワークロードは、思いつきで作ると「狙った通りのノイズが出ない」ことがよくあります。本書では、各ワークロードのマニフェストの先頭に「踏むと想定するupstreamルール」をコメントで明記してから実装し、実測して外れたら理由を書き足す、という手順を踏みました。

```yaml
# N1: 設定リローダー（自作コントローラ）
# ConfigMap を定期的に API サーバーから取得する。オペレータ／コントローラによくある形。
# 想定ルール: Contact K8S API Server From Container
```

実際、この手順で何度も想定が外れました。例えば：

- **N2「起動時にpipでgunicornを入れるアプリ」は`Drop and execute new binary in container`を踏むと想定したが、実測では発火しなかった。** `proc.is_exe_upper_layer=true`は、コンテナのベースイメージに無い**実行ファイル**が実行されたときに真になる条件です。`pip install`で入るgunicornはPythonスクリプトで、execveされるのはベースイメージに含まれる`python3.12`自体なので、この条件を満たしません。代わりに「起動時に静的ELFバイナリ（`yq`）をダウンロードして実行する」ワークロード（N2b）に差し替えて、ようやく狙い通り発火しました
- **N6「`truncate -s 0`でログを切り詰める」は`Clear Log Activities`を踏むと想定したが発火しなかった。** `truncate`はftruncateシステムコールを使い、`open`時の`O_TRUNC`フラグを立てません。ルールの条件は`evt.arg.flags contains "O_TRUNC"`なので、シェルのリダイレクト（`: > file`、これは`open`に`O_TRUNC`を使う）に変えて発火を確認しました

この「想定→実装→実測→外れたら理由を記録」のサイクルこそが、第3章で扱う「conditionを読む」力の実践訓練になっています。

## 2.4 正常業務ワークロード7種

最終的に用意したのは次の7種類です（詳細な条件式の読み解きは第3章・第6章で扱います）。

| ID | ワークロード | namespace | 想定ルール |
|---|---|---|---|
| N1 | 設定リローダー（APIサーバーをポーリング） | apps | Contact K8S API Server From Container |
| N2b | 設定変換ジョブ（起動時にELFバイナリを取得・実行） | apps | Drop and execute new binary in container |
| N3b | 外形監視（ping） | ops | Redirect STDOUT/STDIN to Network Connection in Container |
| N4 | コンプライアンスジョブ（`/etc/shadow`読み取り） | ops | Read sensitive file untrusted |
| N5 | シークレット混入チェック（grep） | ops | Search Private Keys or Passwords |
| N6 | ログローテーション | apps | Clear Log Activities |
| N7 | SREの`kubectl exec`調査 | ops | Terminal shell in container / Packet socket created in container |

これらをまとめて動かし、Falcoのログを集計するスクリプトも用意しました。

```bash
#!/usr/bin/env bash
# tuning/scripts/collect-alerts.sh（要旨）
kubectl -n falco logs ds/falco -c falco --since="$SINCE" | grep '^{' > "$OUT"
jq -r '[.rule, (.output_fields["k8s.ns.name"]//"-"), (.output_fields["container.image.repository"]//"-")] | @tsv' "$OUT" \
  | sort | uniq -c | sort -rn
```

何もチューニングしていない状態で、これら7種類を15分ほど動かした結果が次の表です。これが第6章でチューニングしていく「ベースライン」になります。

```
   4 Contact K8S API Server From Container   apps   docker.io/curlimages/curl
   2 Terminal shell in container             ops    docker.io/nicolaka/netshoot
   2 Search Private Keys or Passwords        ops    docker.io/library/alpine
   2 Read sensitive file untrusted            ops    docker.io/library/alpine
   2 Packet socket created in container       ops    docker.io/nicolaka/netshoot
   2 Drop and execute new binary in container apps   docker.io/library/alpine
   1 Clear Log Activities                     apps   docker.io/library/alpine
```

## 2.5 他クラスタのイベントが混ざる問題（kind特有の注意）

Docker Desktop上で複数のkindクラスタを同時に動かしていると、**modern_ebpfドライバのFalcoは、同じホストの他クラスタのコンテナのイベントまで拾ってしまうことがあります。** これはeBPFがホストのLinuxカーネル全体のsyscallを観測する以上避けられず、姉妹本のラボでも同じ現象が報告されています。

対策として、集計スクリプトでは「自ノードのcontainerdが把握しているコンテナID」に絞り込んでいます。

```bash
IDS=$(docker exec "$NODE" crictl ps -a -q | cut -c1-12 | jq -R . | jq -sc .)
jq -c --argjson ids "$IDS" \
  'select(.output_fields["container.id"] as $c | ($ids | index($c)) != null or (.output_fields["k8s.ns.name"]//null)!=null)'
```

複数クラスタでラボを運用する場合は、最初からこのフィルタを前提にしておくことを勧めます。
