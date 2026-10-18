---
title: "第4章：Initial Access - コンテナへの侵入"
---

# 第4章：Initial Access - コンテナへの侵入

## この章で学ぶこと

- 攻撃者がKubernetesクラスタへの最初の足がかりを得る4つの代表的な経路
- Lab 1〜4の実験手順とFalco／Audit Logsでの観測結果（kindクラスタでの実機検証）
- 初期侵入の段階でどこまで検知できて、どこが観測の空白になるか

本章から、第3章で構築したラボを使って実際に攻撃チェーンを再現していきます。扱うのはMITRE ATT&CK for Containersの**Initial Access**戦術に対応する4つの手法です。すべて[k8s-attack-runtime-security-lab](https://github.com/keitahigaki-prog/k8s-attack-runtime-security-lab)のkindクラスタ上で実機検証しています。

---

## Lab 1: 公開Webアプリ脆弱性経由の侵入

- **MITRE ATT&CK for Containers**: T1190 (Exploit Public-Facing Application)
- **前提**: `vulnerable-webapp`（`/ping?host=`パラメータをシェルに直接渡す自作のコマンドインジェクション脆弱性）を`lab` namespaceにデプロイ

```bash
curl "http://vulnerable-webapp.lab.svc/ping?host=127.0.0.1;id"
```

**結果**: 攻撃は成立し、`id`コマンドが実行されてコンテナ内でroot権限を確認できた。

```
uid=0(root) gid=0(root) groups=0(root),1(bin),...
```

### 実機検証で判明した重大な誤り：標準ルールは検知できない

当初「標準ルール`Terminal Shell in Container`が反応する」という想定で執筆していたが、**実機では一切検知されなかった**。Falcoの実ルール定義を確認すると：

```yaml
- rule: Terminal shell in container
  condition: >
    spawned_process and container and shell_procs
    and proc.tty != 0 and container_entrypoint
    and not user_expected_terminal_shell_in_container_conditions
```

`proc.tty != 0`——つまり**ターミナルが接続されていること**が条件に含まれている。これは`kubectl exec -it`のような対話的侵入を想定したルールで、**Webアプリの脆弱性経由でプログラム的にシェルが起動するケース（TTYなし）はそもそも検知対象外**だった。

### カスタムルールでの検知（1回目は失敗、2回目で成功）

最初に書いたカスタムルールは、親プロセス名を直接指定するものだった：

```yaml
condition: spawned_process and container and shell_procs
  and proc.pname in (python3, node, nginx, ...) and proc.tty=0
```

これも**発火しなかった**。原因は、Falcoのプロセスキャッシュのタイミングにより`proc.pname`がこのケースでは`<NA>`（未解決）になっていたため。`container_entrypoint`マクロ（`not proc.pname exists`を「エントリポイント相当」として扱う）を使った版に直したところ検知できたが、**この版も別のコンテナでは再び発火しないことが後の章（Lab 14）で判明**し、最終的には次の最もシンプルな条件に落ち着いた：

```yaml
- rule: Shell Spawned Without TTY
  condition: >
    spawned_process and container and shell_procs and proc.tty=0
```

実機での検知ログ：

```
Critical Shell spawned without a tty (user=root container=app process=sh
  command=sh -c ping -c 1 127.0.0.1;id pod=vulnerable-webapp-... ns=lab)
```

**考察**: 「標準ルールでシェル起動を検知できる」という想定は誤りだった。カスタムルールも、親プロセス名のような「解決されるかどうか環境依存の情報」に頼ると再現性を失う。**TTYの有無という、最もシンプルで頑健な条件に行き着くまでに2回の失敗が必要**だったこと自体が、本書の重要な教訓になっている。

### 副次的発見：kindラボでは他クラスタのsyscallも混入する

同じイベントが、攻撃対象のPodが乗っていない他ノードのFalcoにも（メタデータ未解決の状態で）記録されていた。これは第3章で触れた、kindクラスタがDocker Desktopの単一カーネルを共有するための現象（詳細は第3章を参照）。

## Lab 2: 誤設定・悪意あるイメージの実行

- **MITRE ATT&CK for Containers**: T1204.003 (Malicious Image), T1071 (Application Layer Protocol)
- **前提**: 外部マルウェア配布元には接続せず、**クラスタ内に自前で立てたC2サーバ**（固定ClusterIP `10.96.99.99:4444`）に対して、起動時にビーコン接続する模擬バックドア`backdoor-demo`をデプロイ

```bash
kubectl apply -f lab/manifests/02-c2-and-backdoor.yaml
```

**結果**: ビーコン接続は成立（C2サーバから`c2-ack`応答を確認）。

### 実機検証で判明した誤り：標準ルール・素朴なカスタムルールのどちらも失敗

標準ルールでは、ビーコン送信側（クライアント）の接続自体は検知されなかった（発火したのは応答側`c2-server`の`nc -e`使用に対する`Netcat Remote Code Execution in Container`のみで、別物）。

最初に書いたカスタムルールは、標準の`outbound`マクロを再利用するものだった：

```yaml
condition: outbound and fd.sip in (known_malicious_ips)
```

**これも発火しなかった**。原因は`outbound`マクロの定義にあった：

```yaml
- macro: outbound
  condition: >
    ((evt.type = connect or ...) and (fd.typechar = 4 or fd.typechar = 6) and ...)
```

このマクロは、**RFC1918プライベートアドレス空間（`10.0.0.0/8`等）を「内部通信だから信頼できる」として暗黙に除外**していた。Kubernetesのservice CIDR（`10.96.0.0/12`）はこの範囲に含まれるため、**C2サーバをクラスタ内のプライベートIPに置いた時点で、標準マクロに依存するルールは原理的に検知不能**になる。

### 修正版カスタムルール（実機確認済み）

`outbound`マクロを使わず、`evt.type=connect`を直接評価する形に変更：

```yaml
- list: known_malicious_ips
  items: [10.96.99.99]

- rule: Outbound Connection to C2 Server
  condition: >
    evt.type=connect and evt.dir=< and (fd.typechar=4 or fd.typechar=6)
    and fd.sip in (known_malicious_ips)
  priority: CRITICAL
```

```
Critical Outbound connection to C2 server (command=nc
  connection=10.244.2.9:35551->10.96.99.99:4444 container=backdoor-agent
  pod=backdoor-demo ns=lab)
```

**考察**: 「カスタムルールを書けば解決する」という単純な話ではなく、**カスタムルールが依存する標準マクロ自体に、プライベートIP＝内部＝信頼できるという暗黙の前提が埋め込まれている**ことが分かった。クラスタ内に設置されたC2中継や横展開の着地点は、この前提が通用しない典型例。

## Lab 3: Kubelet誤公開APIの悪用

- **MITRE ATT&CK for Containers**: T1552.007 (Container API)
- **前提**: kubeletの読み取り専用ポート（10255）が誤って外部に公開された状態を想定

```bash
docker exec attack-lab-worker curl -s -m 3 http://localhost:10255/pods
docker exec attack-lab-worker curl -sk -m 3 https://localhost:10250/pods
```

### 実機検証で判明した重大な事実：この攻撃は現在のKubernetesでは成立しない

```
--- 10255 ---
RC=7   # Connection refused — ポート自体がlistenしていない

--- 10250 (anonymous) ---
Unauthorized
```

kubeletの設定を確認すると：

```yaml
authentication:
  anonymous:
    enabled: false
authorization:
  mode: Webhook
```

**読み取り専用ポート10255は、そもそもlistenしていなかった**。セキュアポート（10250）は生きているが、`anonymous.enabled: false`と`Webhook`認可により、匿名リクエストは`Unauthorized`で拒否される。`system:anonymous`への過剰な権限付与も存在しないことを確認した。

本Labの元ネタであるTesla社の事例（2018年）やKinsingキャンペーン（2020年〜）は、**当時のkubeletのデフォルト設定（`--anonymous-auth=true`がデフォルトだった時代）を前提にしたもの**であり、**現在のkubeadm/kind/マネージドKubernetesのデフォルトでは、この経路はすでに塞がれている**。

**Falcoの検知結果／Audit Logsの記録**: 対象外（そもそも攻撃が成立しないため検知の問題ではない）

**考察**: 本Labの価値は「検知できるか」ではなく、**「セキュリティは時間とともに変化する」ことを示す実証データ**にある。2018年当時は深刻な脅威だったものが、現在のデフォルト設定では成立しない。Lab 3を実際に成立させるには、意図的に`--anonymous-auth=true`を復元する必要があり、それ自体が「この設定変更がなぜ危険か」を示す教材になる。

## Lab 4: kubeconfig／Secret漏洩経由の侵入

- **MITRE ATT&CK for Containers**: T1552.001 (Credentials In Files)
- **前提**: CI/CDが使う`deploy-bot`というServiceAccountに、クラスタ全体のSecret読み取り権限（過剰権限）を付与し、そのトークンが漏洩した想定

```bash
TOKEN=$(kubectl create token deploy-bot -n lab --duration=1h)
APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/secrets"
```

**結果**: 攻撃は成立。全Namespace横断でSecret一覧を取得できた。

**Falcoの検知結果**: 対象外（クラスタ外から直接APIサーバにアクセスするため、ノード上のsyscallには現れない）

**Audit Logsの記録（実測）**:

```json
{"verb": "list", "user": {"username": "system:serviceaccount:lab:deploy-bot", ...,
  "extra": {"authentication.kubernetes.io/credential-id": ["JTI=d30fbc1f-..."]}},
 "objectRef": {"resource": "secrets", "apiVersion": "v1"}, "responseStatus": {"code": 200}}
```

本文の想定どおり、**Audit Logsに漏洩トークンによる全Secret一覧取得が正確に記録されていた**。これはLab 1〜3と異なり、実機結果が当初の想定と一致した数少ないケース。

**考察**: ここはFalcoではなくAudit Logsが主役になる、明確な役割分担の例。短命トークン（`kubectl create token`で発行）であっても、JTIクレームとして追跡可能であることも確認できた。

---

## 本章のまとめ

| Lab | 手法 | 標準ルールで検知 | カスタムルールで検知 | 観測できた層 |
|---|---|---|---|---|
| 1 | 公開Webアプリ脆弱性 | ❌ | ✅（2回の失敗を経て） | ノード内 |
| 2 | 悪意あるイメージ（C2ビーコン） | ❌ | ✅（1回目の素朴な実装は失敗） | ノード内 |
| 3 | kubelet誤公開API | N/A（攻撃自体が不成立） | N/A | 現在のデフォルトでは観測不要 |
| 4 | kubeconfig漏洩 | - | - | APIサーバ（Audit Logsのみで十分） |

4本の実験を通して、**「標準ルールが思ったように動かない」「カスタムルールも標準マクロの前提に足を引っ張られる」「そもそも攻撃が成立しない」という、本文執筆時には想定していなかった3パターンの"つまずき"**が早速現れました。次章では、侵入後にコンテナ内部で何が実行されるか（Execution）を見ていきます。

## 参考資料

- [MITRE ATT&CK T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [Kubelet authentication/authorization（公式ドキュメント）](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)
- [Falco Default Rules（falcosecurity/rules）](https://github.com/falcosecurity/rules)
- [Kubernetes Audit Logging（公式ドキュメント）](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [k8s-attack-runtime-security-lab（本書の実験コード一式）](https://github.com/keitahigaki-prog/k8s-attack-runtime-security-lab)
