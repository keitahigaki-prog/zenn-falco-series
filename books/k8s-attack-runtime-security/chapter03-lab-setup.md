---
title: "第3章：攻撃・観測ラボの構築"
---

# 第3章：攻撃・観測ラボの構築

## この章で学ぶこと

- 実験ラボ全体の設計方針（どこまでをラボに含め、どこを境界として切るか）
- わざと脆弱にしたワークロードの用意の仕方
- Falco（eBPFドライバ）のセットアップ
- Kubernetes Audit Logsの有効化
- ネットワーク観測（CNI／pcap）の下準備
- 実験結果を再現可能な形で記録する方法

---

## ラボ環境の全体設計

前章で整理した「3つの境界線」（ノード内 / APIサーバ / クラウドAPI）をすべて観測できる状態にしてから、攻撃実験を始めます。そうしないと、「検知できなかった」のが**ルールの不備なのか、そもそも観測範囲外だったのか**を判別できません。

![図3-1：実験ラボの全体アーキテクチャ](/images/fig-ch03-lab-architecture.png)

**なぜself-managed Kubernetesを選ぶのか**：本書の実験の一部（第7章のContainer Escape、第6章の一部のPrivilege Escalation手法）は、コントロールプレーンやノードの設定を直接いじる必要があります。GKE/EKSのようなマネージドサービスではコントロールプレーンに手が届かないため、**再現実験はself-managed（kubeadmやkindベース）のクラスタで行い、マネージド環境との差分は都度注記する**方針にします。本番でマネージドKubernetesを使っている読者は、「この実験はマネージド環境では起きない／別の形で現れる」という注記を必ず確認してください。

ラボはクラウド（コスト最適化のため最小構成）とローカル（kind）の両方で動くように構築します。本書の実験はすべて、ローカル（kind、Docker Desktop上）で実機検証済みです。再現用のコード一式は[k8s-attack-runtime-security-lab](https://github.com/keitahigaki-prog/k8s-attack-runtime-security-lab)として公開しています。

**kindクラスタに特有の注意点（実機検証で判明）**: kindの各"ノード"は、独立したVMやベアメタルではなく、**同一のDocker Desktop VM（同じLinuxカーネル）上で動くコンテナ**です。そのため、**あるkindクラスタのFalcoが、同じDocker Desktopホスト上で動く別のkindクラスタのsyscallまで観測してしまう**ことが実機で確認できました。ノードごとに正しいPod/コンテナメタデータが付くのは「そのコンテナが実際に動いているノード」のFalcoだけで、他のFalcoインスタンスのログにも同じイベントが`k8s_pod_name=<NA>`という形で混入します。複数のkindクラスタを同じマシンで並行運用している場合は、ログを**解決済みメタデータの有無でフィルタする**運用が必須です（本番の、ノードが物理的/仮想的に分離されたクラスタではこの問題は起きません）。

## 脆弱なワークロードの用意

攻撃実験には、意図的に脆弱にしたワークロードが必要です。本書では次の3種類を用意します。

| ワークロード | 脆弱性の種類 | 主に使う章 |
|---|---|---|
| `vulnerable-webapp` | `/ping?host=`パラメータをシェルに直接渡すコマンドインジェクション（Python自作、既知CVEの模倣ではなく最小構成の脆弱コード） | 第4章 |
| `misconfigured-pod` | 特権モード・hostPath | 第6・7章 |
| `over-privileged-sa-pod` / `deploy-bot` | Secret取得・（後に`pods/exec`も追加する）過剰権限ServiceAccountを紐付け | 第6・8章 |
| `cap-abuse-pod` | `CAP_SYS_PTRACE`を追加 | 第6章 |
| `host-pid-pod` / `host-pid-ptrace-pod` | `hostPID: true`（単体、および`CAP_SYS_PTRACE`併用） | 第7章 |
| `debug-service` | 認証なしでPOST bodyをシェル実行する模擬デバッグサービス | 第8章 |
| `c2-server` / `attacker-listener` | クラスタ内に自前で立てる攻撃者側インフラ（固定ClusterIP） | 第4・5章 |

```yaml
# misconfigured-pod（例）: 意図的に特権コンテナ化
apiVersion: v1
kind: Pod
metadata:
  name: misconfigured-pod
spec:
  containers:
    - name: app
      image: alpine:3.19
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-root
          mountPath: /host
  volumes:
    - name: host-root
      hostPath:
        path: /
```

**注意**: これらのマニフェストは実験ラボ専用です。本番環境や共有クラスタには絶対に適用しないでください。リポジトリの`lab/manifests/`配下には、誤適用防止のためnamespace分離と`NetworkPolicy`によるラボ外への通信遮断を同梱しています。

## Falco + eBPFドライバのセットアップ

前作でも扱った内容ですが、本書のラボでは**modern eBPF**ドライバを前提にします（カーネルモジュール版は本書では扱いません）。

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set driver.kind=modern_ebpf \
  --set tty=true
```

ラボ用途では、**標準ルールセットに加えて、本書で扱う攻撃チェーンに対応したカスタムルールファイルを後の章で順次追加**していきます。第3章の時点では、まず標準ルールだけが入った状態を「ベースライン」として記録しておきます（第10章の検知カバレッジ評価で、このベースラインとの差分を測るためです）。

```bash
# ベースラインの確認
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50
```

## Kubernetes Audit Logsの有効化

前章で触れた「APIサーバ境界」を埋めるのがAudit Logsです。self-managedクラスタでは、kube-apiserverの起動オプションにAudit Policyを追加します。

```yaml
# audit-policy.yaml（抜粋）
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets", "serviceaccounts"]
  - level: Request
    verbs: ["create", "update", "patch", "delete"]
    resources:
      - group: "rbac.authorization.k8s.io"
  - level: Metadata
```

```bash
# kube-apiserver起動オプション（kubeadm構成の場合は /etc/kubernetes/manifests/kube-apiserver.yaml に追記）
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--audit-log-path=/var/log/kubernetes/audit.log
--audit-log-maxage=7
--audit-log-maxbackup=3
```

`secrets`や`serviceaccounts`、RBAC変更といった**第7・8章で狙われるリソース**を重点的にログレベルを上げているのがポイントです。全リソースを`RequestResponse`にするとログ量が膨大になり、実験ラボでも扱いにくくなるため、攻撃チェーンに即して段階的に絞り込んでいます。

## ネットワーク観測（CNI/pcap）の下準備

第8章のLateral Movement実験では、クラスタ内ネットワークの挙動を観測する必要があります。本書では次の2系統を候補に挙げます。

- **CNIのフローログ**（Calico等、フローログ機能を持つCNIを使う場合は`FelixConfiguration`で有効化）
- **ノード上での`tcpdump`によるパケットキャプチャ**（ピンポイントの実験でのみ使用し、常時稼働はさせません）

```bash
# Calico環境でのフローログ有効化例
calicoctl patch felixconfiguration default --patch \
  '{"spec": {"flowLogsFileEnabled": true, "flowLogsFileIncludeLabels": true}}'
```

**実機検証での注記**: 本書のkindラボは既定のCNI（kindnet）を使っており、**Calicoは導入していません**。そのため第8章の実験では、CNIフローログではなくtcpdump、およびFalco自体のsyscall観測だけで検証しています。Calicoのような高機能CNIへの切り替えは、ネットワーク観測を本格的に使い込みたい場合の発展課題として別途検証してください。

## 実験の記録方法

20本の実験すべてで、再現性を担保するために統一フォーマットを使います。

```markdown
## Lab XX: <実験名>
- MITRE ATT&CK for Containers: <Technique ID>
- 前提: <クラスタ状態・使うワークロード>
- 手順: <実行したコマンド>
- Falcoの検知結果: <ログ抜粋 or 「未検知」>
- Audit Logsの記録: <ログ抜粋 or 「対象外」>
- ネットワーク観測: <該当する場合のみ>
- 考察: <検知できた/できなかった理由>
```

このフォーマットに沿ったログは`lab/results/lab-XX.md`としてリポジトリに蓄積し、第10章・第11章の横断分析（研究A・B・C）では、この20本分の記録を集計して結論を導きます。

---

次章からは、いよいよ実際の攻撃チェーンの再現に入ります。まずはInitial Access——攻撃者がコンテナに最初の足がかりを得るところからです。

## 参考資料

- [Falco Helm Charts（falcosecurity/charts）](https://github.com/falcosecurity/charts)
- [Falco公式ドキュメント](https://falco.org/docs/)
- [Kubernetes Audit Logging（公式ドキュメント）](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Falcosidekick（falcosecurity/falcosidekick）](https://github.com/falcosecurity/falcosidekick)
- [Pod Security Standards（公式ドキュメント）](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [kind（Kubernetes IN Docker）](https://kind.sigs.k8s.io/)
