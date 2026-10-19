---
title: "第7章 upstreamルールの扱い方"
---

# 第7章 upstreamルールの扱い方

Falcoを運用していると必ず直面する問題があります。「upstream（`falcosecurity/falco`が配布する`falco_rules.yaml`）は定期的に更新されるが、こちらは手を入れてある。どう両立させるか」です。

本章の内容は、すべてtuning-lab（Falco 0.45.0、Helm chart `falcosecurity/falco` 9.2.0）上で実際に`falco -V`（ルールの構文検証）とアラート出力を使って検証した結果です。

## 8.1 ルールファイルの読み込み順序

Helm chartのデフォルト設定（`falco.yaml`）には、次の`rules_files`が書かれています。

```yaml
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml
  - /etc/falco/rules.d
```

`falco_rules.local.yaml`は、カスタムルールを何も指定していない場合は**ファイルとして存在しません**。Falcoはそれを検知すると黙ってスキップします（エラーにはなりません）。実際に流れたログは次の通りです。

```
Loading rules from:
   /etc/falco/falco_rules.yaml           | schema validation: ok
   /etc/falco/rules.d/custom-a.yaml      | schema validation: ok
   /etc/falco/rules.d/custom-b.yaml      | schema validation: ok
```

ここで重要なのは2点です。

1. **`falco_rules.yaml`（upstream）は常に最初に読み込まれる**
2. **`rules.d/`配下はファイル名のアルファベット順**で読み込まれる（この例では`custom-a.yaml`→`custom-b.yaml`）

複数のカスタムファイルで同じルールをoverrideしている場合、**アルファベット順で後に読まれたファイルの内容が最終的に勝ちます**。チームで分担してファイルを分ける場合、この順序に依存した事故を避けるため、「誰がどのファイルで何をoverrideしているか」を1箇所（README等）にまとめておくことを勧めます。

## 8.2 override: 同名ルールを後から書き換える

Falcoでは、**同じ名前のルール/マクロ/リストを後続のファイルで再度定義すると、追記または上書きができます。** これがupstreamルールに手を入れる基本手段です。`override`キーで「どう反映するか」を指定します。

### condition の override

```yaml
# 検証用のベースルール（本来はupstreamのルールだが、分かりやすさのため単純化）
- rule: Canary Base Rule
  condition: spawned_process and proc.name="canaryproc"
  output: "canary base fired (cmd=%proc.cmdline)"
  priority: NOTICE

# append: 元の条件に "and <追加条件>" が連結される
- rule: Canary Base Rule
  condition: " and proc.args contains \"MUST_NOT_MATCH\""
  override:
    condition: append
```

tuning-labで実測したところ、`override.condition: append`は**元のconditionの文字列にそのまま追加条件を連結**し、全体として**論理AND**になります。

- 追加条件を恒偽にする → ベースが真でも全体は偽になり、**発火しなくなる**（＝条件を満たさないよう絞り込んだのと同じ）
- 追加条件を恒真にする → ベースの真偽がそのまま結果になる（＝何も変えていないのと同じ）

```yaml
- rule: Canary Replace Target
  condition: spawned_process and proc.name="neverused"
  output: "..."
  priority: NOTICE

# replace: 元の条件を完全に捨てて差し替える
- rule: Canary Replace Target
  condition: spawned_process and proc.name="canaryproc2"
  override:
    condition: replace
```

`override.condition: replace`は**元のconditionを完全に破棄**し、新しいconditionに置き換えます。実測では、ベースの条件（`proc.name="neverused"`）がどれだけ満たされなくても、置き換え後の条件（`proc.name="canaryproc2"`）だけで発火しました。

> **使い分けの指針**
> - **append**: upstreamの検知意図はそのまま残し、特定の状況だけ除外・追加したい時。ルール名とdescの意味がズレない
> - **replace**: upstreamの検知意図そのものを変えたい時。この場合、`desc`も合わせて書き換えないと「ルール名と実際の中身がズレる」事故になる

### priority の override

```yaml
- rule: Terminal shell in container
  priority: INFORMATIONAL
  override:
    priority: replace
```

upstreamの`Terminal shell in container`は本来`priority: NOTICE`です。tuning-labで`kubectl exec -it`を実行して確認したところ、override適用前は`Notice`、適用後は`Informational`としてアラートが記録されました。**ルールは無効化せず、「監査ログとしては残すが優先度は下げる」運用**が、`priority`のoverrideだけで実現できます。`disabled: true`にすると検知そのものが消えてしまうので、この差は実務上大きいです。

### exceptions の override（第6章の本題）

```yaml
- rule: Contact K8S API Server From Container
  exceptions:
    - name: apps_config_reloader
      fields: [k8s.ns.name, "k8s.pod.label[app]", container.image.repository, proc.name]
      values:
        - [apps, config-reloader, docker.io/curlimages/curl, curl]
  override:
    exceptions: append
```

`exceptions: append`は、upstream側の`exceptions:`フィールド（多くの場合は空リスト）を壊さずに項目を追加します。第6章で詳しく扱いますが、tuning-labでは、正常業務ワークロード7種に対してこの形の例外を5箇所設定した結果、ベースラインで15件出ていたアラートが2件まで減りました（残り2件は`priority` overrideで「監査として残す」と判断したもの）。

## 8.3 存在しないルール名へのoverrideは、起動時にエラーで止まる

```yaml
- rule: This Rule Does Not Exist Anywhere
  condition: " and proc.name=\"x\""
  override:
    condition: append
```

このルールを読み込ませると、Falcoは起動せずに次のエラーを出します。

```
LOAD_ERR_VALIDATE (Error validating rule/macro/list/exception objects):
Rule uses 'append' or 'override.<key>: append' but no rule by that name already exists
```

これは地味に重要な性質です。**upstream側でルール名が変わった（メジャーバージョンアップでリネームされた等）場合、こちらのoverrideは「サイレントに無視される」のではなく「起動時に検出される」。** 裏を返せば、Falcoのバージョンを上げたときは`falco -V`（第10章で扱うCIでの検証）を必ず通し、overrideの対象ルールが消えていないかを確認する運用が成立します。

## 8.4 upstreamの更新に追従する

upstreamの`falco_rules.yaml`は、マイナーアップデートのたびにルールの追加・条件の変更・マクロのリネームが入ります。チューニング済みの環境を壊さずに追従するための手順は次の通りです。

1. **新しい`falco_rules.yaml`を取得し、現行版とdiffを取る。** 今回使った`helm get values`や`helm template`で、実際にPodに配布される内容を確認できます
2. **自分がoverrideしているルール名が、diffでどう変わったかを確認する。** ルール名が変わっていればoverrideは「存在しないルールへのoverride」としてエラーになるので、`falco -V`を通せば機械的に検出できます
3. **conditionの中身が変わっていたら、自分のexceptions/overrideが今も意味を持つか再検証する。** 例えば`user_known_*`マクロの置き場所が変わっていないか、フィールド名が変わっていないかを確認します
4. **ステージング相当のラボ（tuning-lab）で、正常業務ワークロードを一通り動かし直し、チューニング後のアラート件数を比較する。** 第6章・第9章の手順がそのまま使えます

## 8.5 まとめ

- ルールファイルは upstream → ローカル全体（存在すれば）→ `rules.d/*`（アルファベット順）の順に読み込まれる
- `override.condition: append`は論理AND、`replace`は完全な差し替え。意味が違うので使い分ける
- `override.priority: replace`で、ルールを消さずに優先度だけ調整できる
- 存在しないルール名へのoverrideは起動時エラーになる。これを`falco -V`のCIチェックに組み込むことで、upstream追従時の事故を機械的に検出できる
