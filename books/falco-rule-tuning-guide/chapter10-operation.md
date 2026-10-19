---
title: "第10章 本番運用への反映"
---

# 第10章 本番運用への反映

ここまでの章で、tuning-lab上でのチューニング手法を一通り扱いました。本章では、それをどう本番に反映し、どう運用し続けるかを扱います。架空の理想論ではなく、本書のラボで実際に行った作業をベースにしています。

## 10.1 Kubernetes特有の落とし穴（まとめ）

第4章・第6章で個別に扱った、Kubernetesのメタデータに起因する落とし穴を、本番投入前のチェックリストとして整理し直します。

### メタデータ解決の race

> **実測（第6章）**: Pod起動直後の短命プロセスでは、`k8s.ns.name`や`k8s.pod.label[*]`が未解決（`<NA>`）のまま検知されることがあります。同じイベントで`k8s.pod.name`は解決されているのに`k8s.pod.label[app]`だけ未解決、というケースも確認しました。

本番投入前に確認すべきこと：

- [ ] 例外やチューニングのキーに`k8s.pod.label[*]`を使っている箇所を洗い出す
- [ ] 可能なら`k8s.pod.name`（`startswith`で前方一致）か、メタデータに依存しない`fd.name`/`proc.exepath`に差し替える
- [ ] どうしてもlabelでしか絞れない場合、「race時は例外が効かずアラートが発火する」ことを許容する旨をドキュメント化する（race時は過検知になるだけで、見逃しにはならないため安全側に倒れる）

### CronJob・Jobのpod名はサフィックス付きで生成される

第6章N4で使った`password-expiry-audit-29872076-f5v9b`のような名前は、`k8s.pod.label[batch.kubernetes.io/job-name]`を`startswith`で前方一致させる必要があります。完全一致で書いて「なぜか効かない」と詰まるのは典型的な事故です。

### 複数クラスタ混入（kind/ローカル検証特有）

本番のマネージドKubernetes環境では通常起きませんが、複数のkindクラスタを同じDocker Desktop上で動かして検証する場合は、第2章・第8章で扱った「他クラスタのイベント混入」に注意してください。

## 10.2 ルールの配布方法：GitOpsでの管理

本書のtuning-labでは、チューニング済みのルールファイル（`tuning-rules.yaml`）をHelmの`customRules`値として配布しました。

```bash
helm upgrade falco falcosecurity/falco --version 9.2.0 -n falco \
  -f falco-values.yaml \
  --set-file 'customRules.tuning-rules\.yaml=rules/tuning-rules.yaml'
```

この方式のまま本番に持っていく場合、次の運用が最低限必要です。

1. **`tuning-rules.yaml`をGit管理し、変更はPull Requestを通す。** 第6章で見たように、1つの例外が「どのワークロードの、どういう理由の除外か」をコメントで残す規約を徹底する
2. **マージ前にCIで`falco -V`を実行する。** 第7章で確認した通り、存在しないルール名へのoverrideやYAML構文エラーは`falco -V`で機械的に検出できます

```yaml
# .github/workflows/falco-rules-ci.yml（例）
- name: Validate Falco rules
  run: |
    docker run --rm -v "$PWD/rules:/rules" falcosecurity/falco:0.45.0 \
      falco -V /etc/falco/falco_rules.yaml -V /rules/tuning-rules.yaml
```

3. **第9章の回帰テストをCIに組み込む。** 姉妹本の攻撃シナリオを再生し、チューニング後も検知が残っているかを自動チェックする。最低限、「このPRで変更したルールに関連する攻撃シナリオ」だけでも流す

## 10.3 段階的な導入：disableせず、priorityで慣らす

第6章N7で使った`priority`のoverrideは、本番導入の初期段階でも有効な手段です。

```yaml
- rule: <新しく有効化したいルール>
  priority: INFORMATIONAL
  override:
    priority: replace
```

新しいルール（またはupstreamの更新で条件が変わったルール）を本番に入れるとき、いきなり`WARNING`以上で通知を飛ばすのではなく、最初は`INFORMATIONAL`に落として「どれだけ・何に対して発火するか」を数日〜1週間観察してから、優先度を戻すという運用が、本章の実測（第6章のベースライン計測）と同じ手法で行えます。

## 10.4 例外の棚卸し

`exceptions`はコメントで理由を書いていても、ワークロードが廃止されれば不要になります。本書のtuning-rules.yamlの各ブロックには、対象ワークロードと理由をコメントで明記していますが、これは「後から見て、まだ必要かを判断できるようにする」ためです。

- [ ] 例外の`name`フィールド（N1, N4等のように用途が分かる名前を付ける）をワークロード名と対応付ける
- [ ] 対象ワークロードが廃止されたら、例外も同じPRで削除する運用をルール化する
- [ ] 定期的に（四半期に1回など）、`exceptions`一覧と実在するワークロードを突き合わせる

## 10.5 まとめ

- Kubernetes固有の落とし穴は、ほぼすべて「メタデータの解決タイミング」に起因する。本番投入前に、例外のキーがメタデータ依存かどうかを確認する
- ルールファイルはGit管理し、CIで`falco -V`と回帰テスト（第9章）を通す
- 新しいルール・チューニングは、`priority`のoverrideで慣らしてから正式運用に入れられる
- 例外は「なぜ入れたか」をコメントに残し、ワークロードの廃止と同時に削除する運用を組み込む
