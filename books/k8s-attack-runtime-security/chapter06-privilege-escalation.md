---
title: "第6章：Privilege Escalation - 権限昇格"
---

# 第6章：Privilege Escalation - 権限昇格

## この章で学ぶこと

- コンテナ内の制限された権限から、より強い権限を得る4つの代表的な手法
- Lab 7〜9の実験手順とFalco・RBAC監査それぞれの観測結果
- 「コンテナの中での昇格」と「クラスタAPIでの昇格」の違い

本章ではMITRE ATT&CK for Containersの**Privilege Escalation**戦術を扱います。第3章で用意した`misconfigured-pod`（特権コンテナ）と`over-privileged-sa`（過剰権限のServiceAccount）を使います。

---

## Lab 7: 特権コンテナ・hostPath悪用

- **MITRE ATT&CK for Containers**: T1611 (Escape to Host の前段階), T1612 (Build Image on Host)
- **前提**: 第3章で作成した`misconfigured-pod`（`privileged: true` + `hostPath: /`をマウント）

```bash
kubectl exec -it misconfigured-pod -- sh
# コンテナ内で
chroot /host
cat /etc/shadow
```

特権コンテナからホストのルートファイルシステムをマウントしているため、コンテナの中にいながらホストのファイルに直接アクセスできます。

**Falcoの検知結果**:

```
18:21:02.330541000: Critical Sensitive File Read via Mounted Host Path (user=root file=/host/etc/shadow container=misconfigured-pod)
18:21:02.331102000: Warning chroot Executed in Privileged Container (command=chroot parent=sh container=misconfigured-pod)
```

標準ルールの`Read sensitive file untrusted`と、特権コンテナでの`mount`/`chroot`に反応するルールが両方発火しました。

**考察**: `privileged: true`と`hostPath`の組み合わせは、**検知よりも予防（Admission Controller / Pod Security Standards）で塞ぐべき設定**です。本書では検知を主眼に置いていますが、実運用ではOPA GatekeeperやKyvernoでこの種のPodを作成不可にする方が優先度が高いことを明記しておきます。

## Lab 8: ServiceAccountトークン奪取とRBAC悪用

- **MITRE ATT&CK for Containers**: T1552.007 (Container API), T1078.004 (Valid Accounts: Cloud Accounts)
- **前提**: `over-privileged-sa`（`cluster-admin`相当のRoleBindingを持つServiceAccount）が紐付いたPod

```bash
kubectl exec -it over-privileged-sa-pod -- sh
# コンテナ内で
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/clusterrolebindings
```

**Falcoの検知結果**:

```
18:25:40.119203000: Notice ServiceAccount Token Read (container=over-privileged-sa-pod file=/var/run/secrets/kubernetes.io/serviceaccount/token)
```

トークンファイルの読み取り自体は検知できますが、**このトークンを使ってAPIサーバに対して何をしたか**はFalcoの可視範囲外です。

**Audit Logsの記録**:

```json
{
  "verb": "list",
  "objectRef": {"resource": "clusterrolebindings", "apiGroup": "rbac.authorization.k8s.io"},
  "user": {"username": "system:serviceaccount:lab:over-privileged-sa"},
  "sourceIPs": ["10.0.3.12"],
  "responseStatus": {"code": 200}
}
```

ここでAudit Logsが本領を発揮します。**ServiceAccountトークンがどのAPI操作に使われたか**は、Falcoではなく必ずAudit Logsで追う必要があります。

**考察**: Lab 8は本書で最も「2つのデータソースの役割分担」が明確に出る実験です。**「トークンが読まれた」のはFalco、「トークンで何をされたか」はAudit Logs**——この2つをセットで見て初めて攻撃の全体像が分かります。

## Lab 9: Linux Capabilities悪用（SYS_ADMIN等）

- **MITRE ATT&CK for Containers**: T1611
- **前提**: `CAP_SYS_ADMIN`を付与されたコンテナ

```yaml
securityContext:
  capabilities:
    add: ["SYS_ADMIN", "SYS_PTRACE"]
```

```bash
# コンテナ内で、SYS_PTRACEを使い他プロセスのメモリを覗く
kubectl exec -it cap-abuse-pod -- sh
ptrace_test --pid=<host-process-pid>
```

**Falcoの検知結果**:

```
18:31:55.772098000: Warning Container with Sensitive Capability Added (container=cap-abuse-pod capability=CAP_SYS_PTRACE)
```

**考察**: Capabilitiesの悪用自体よりも、**「そもそもそのCapabilityが付与された時点」で検知する**アプローチが効果的でした。これは第10章で扱う「実行後の検知」と「構成時点での検知（Admission/Posture側）」の役割分担にもつながる論点です。

---

## 本章のまとめ

| Lab | 手法 | Falco | Audit Logs | ポイント |
|---|---|---|---|---|
| 7 | 特権コンテナ・hostPath | ✅ 検知 | - | 予防（Admission）優先の領域 |
| 8 | SAトークン奪取・RBAC悪用 | △ トークン読み取りのみ検知 | ✅ API操作を記録 | Falco × Audit Logsの役割分担が明確 |
| 9 | Capabilities悪用 | ✅ 付与時点で検知 | - | 構成時点の検知が効果的 |

権限昇格フェーズでは、**「コンテナの中で完結する昇格」はFalcoで、「クラスタAPIに波及する昇格」はAudit Logsで**という分担がより鮮明になりました。次章では、ついにコンテナの境界そのものを突破する「Container Escape」に進みます。
