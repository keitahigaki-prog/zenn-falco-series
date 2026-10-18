---
title: "第6章：Privilege Escalation - 権限昇格"
---

# 第6章：Privilege Escalation - 権限昇格

## この章で学ぶこと

- コンテナ内の制限された権限から、より強い権限を得る3つの代表的な手法
- Lab 7〜9の実験手順とFalco・RBAC監査それぞれの観測結果（実機検証）
- 「コンテナの中での昇格」と「クラスタAPIでの昇格」の違い

本章ではMITRE ATT&CK for Containersの**Privilege Escalation**戦術を扱います。第3章で用意した`misconfigured-pod`（特権コンテナ）と`over-privileged-sa-pod`、`cap-abuse-pod`を使います。

---

## Lab 7: 特権コンテナ・hostPath悪用

- **MITRE ATT&CK for Containers**: T1611 (Escape to Host の前段階)
- **前提**: `misconfigured-pod`（`privileged: true` + hostPath `/`を`/host`にマウント）

```bash
kubectl -n lab exec misconfigured-pod -- sh -c "chroot /host cat /etc/shadow | head -3"
```

**結果**: 攻撃は成立し、ホスト側の`/etc/shadow`を読み出せた。

### 実機検証で判明した訂正：「chroot Executed in Privileged Container」ルールは実在しない

標準ルールセット全体を`grep -i chroot`で検索したが、**chrootに言及するルールは1件も存在しなかった**。実際に検知できたのは次の2つ：

1. 第4章で修正したカスタムルール`Shell Spawned Without TTY`がコマンド全体の実行を捉えた
2. 標準ルール`Sensitive file opened for reading by non-trusted program`が`/etc/shadow`への`openat`を正しく検知した

```
Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow
  process=cat proc_exepath=/host/usr/bin/cat parent=sh command=cat /etc/shadow
```

興味深いのは、**`chroot`後のパス（`/etc/shadow`）がホスト側の実ファイルであっても、Falcoはコンテナのマウント名前空間をまたいで正しくファイルパスを解決し検知できた**点。

**考察**: 「特権コンテナ＋hostPathは検知よりAdmission Controllerでの予防が優先」という結論自体は実機結果でも支持される（chroot専用の検知層が無いことがその裏付けになる）。ルール名の訂正のみが必要。

## Lab 8: ServiceAccountトークン奪取とRBAC悪用

- **MITRE ATT&CK for Containers**: T1552.007 (Container API)
- **前提**: `over-privileged-sa-pod`（第4章で作った過剰権限SA`deploy-bot`を紐付け）

```bash
kubectl -n lab exec over-privileged-sa-pod -- sh -c '
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
wget -qO- --no-check-certificate --header="Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets
'
```

**結果**: 攻撃は成立し、`kube-system`のSecret一覧を取得できた。

### 実機検証で判明した訂正：「ServiceAccount Token Read」ルールも実在しない

実際に発火したのは、自前のシェル検知ルールと、標準ルール`Unexpected connection to K8s API Server from container`：

```
Notice Unexpected connection to K8s API Server from container |
  process=wget command=wget ... --header=Authorization: Bearer eyJhbGci... https://kubernetes.default.svc/...
```

### 重要な副次的発見：Falcoのログ自体がトークン漏洩経路になる

このアラート出力には、**Bearerトークン全体がそのままコマンドラインとして記録されていた**。Falcoのログを外部（Slack等）に転送する運用では、この種の機密情報のマスキングが必要になる——これは本書を書く過程で初めて気づいた、実務上重要な注意点。

### Audit Logsの記録：本文の想定より高精度だった

```json
{"verb": "list", "user": {"username": "system:serviceaccount:lab:deploy-bot", ...,
  "extra": {
    "authentication.kubernetes.io/node-name": ["attack-lab-worker"],
    "authentication.kubernetes.io/pod-name": ["over-privileged-sa-pod"],
    "authentication.kubernetes.io/pod-uid": ["1adc7383-..."]
  }},
 "objectRef": {"resource": "secrets", "namespace": "kube-system"}, "responseStatus": {"code": 200}}
```

当初は「Audit LogsではServiceAccount名とsourceIPsしか分からない」という想定だったが、**実際にはBound Service Account Token（Kubernetes 1.22+で標準化）のおかげで、`extra`フィールドに発行元のPod名・Pod UID・ノード名まで自動的に埋め込まれていた**。

**考察**: 「トークンが読まれた」のはFalco、「トークンで何をされたか」はAudit Logs、という役割分担の骨格は実機でも裏付けられた。ただしルール名の訂正と、Audit Logsの精度がより高いという上方修正が必要。

## Lab 9: Linux Capabilities悪用（SYS_PTRACE）

- **MITRE ATT&CK for Containers**: T1611
- **前提**: `cap-abuse-pod`（`CAP_SYS_PTRACE`を追加）

```bash
kubectl -n lab exec cap-abuse-pod -- sh -c "apk add --no-cache strace; strace -p 1 -f -e trace=none"
```

**結果**: 攻撃は成立し、`strace -p 1`でコンテナのPID 1にアタッチできた。

### 実機検証で判明した訂正：Capability「付与」時点の検知はFalcoの設計上成立しない

当初「Capabilityが付与された構成時点で検知するのが効果的」と書いていたが、**Falcoは実行時のsyscallしか見られないため、この主張自体が成立しない**（付与時点の検知はAdmission Controller/OPA等の役割）。

実機では代わりに、**ptrace syscallそのものを直接検知する標準ルールが複数発火**し、本文の想定より充実した結果が得られた：

```
Critical Executing binary not part of base image | proc_exe=strace exe_flags=EXE_WRITABLE|EXE_UPPER_LAYER
Warning  Detected ptrace PTRACE_ATTACH attempt | process=strace command=strace -p 1 -f -e trace=none
Notice   Detected potential PTRACE_TRACEME anti-debug attempt | process=strace
```

- `Executing binary not part of base image`：`apk add`でインストールしたstraceが、イメージの元レイヤーに存在しないバイナリ（`EXE_UPPER_LAYER`）として検知された
- `Detected ptrace PTRACE_ATTACH attempt`：ptrace syscallそのものをピンポイントで検知。CAP_SYS_PTRACEの「付与」ではなく「実際の悪用」を捉えている

**考察**: 「Capability付与時点の検知が効果的」という当初の結論は撤回し、「**Falcoは`CAP_SYS_PTRACE`の"付与"ではなく"実際の悪用"(ptrace syscall)を直接検知できる**」という、より正確で、かつ実機では想定より充実した結論に差し替える。副産物として、`Executing binary not part of base image`という汎用的に強力なルールの存在も分かった。

---

## 本章のまとめ

| Lab | 手法 | 標準ルールで検知 | カスタムルール/Audit Logs | ポイント |
|---|---|---|---|---|
| 7 | 特権コンテナ・hostPath | ✅（ルール名は要訂正） | - | chroot専用ルールは無いが汎用ルールで捕捉 |
| 8 | SAトークン奪取・RBAC悪用 | ✅（部分、ルール名要訂正） | ✅ Audit Logs（想定より高精度） | Falco×Audit Logsの役割分担、トークン漏洩リスクに注意 |
| 9 | Capabilities悪用 | ✅（想定より充実） | - | 「付与」ではなく「悪用」の検知、という結論に訂正 |

権限昇格フェーズでは、**「標準ルールは思ったより名前も中身も違うが、実効性自体は多くのケースで確認できた」**という、Initial Accessフェーズとはやや異なる傾向が見えました。次章では、ついにコンテナの境界そのものを突破する「Container Escape」に進みます。

## 参考資料

- [MITRE ATT&CK T1611: Escape to Host](https://attack.mitre.org/techniques/T1611/)
- [MITRE ATT&CK T1552.007: Container API](https://attack.mitre.org/techniques/T1552/007/)
- [Pod Security Standards（公式ドキュメント）](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Using RBAC Authorization（公式ドキュメント）](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [capabilities(7) — Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [k8s-attack-runtime-security-lab（本書の実験コード一式）](https://github.com/keitahigaki-prog/k8s-attack-runtime-security-lab)
