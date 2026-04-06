---
title: "第3章: データモデルと脅威管理 — STIX・脅威・武器庫・観測"
---

## 3.1 STIXとは何か

STIX（Structured Threat Information eXpression）は、サイバー脅威情報を構造化して表現するための国際標準フォーマットです。OASISという標準化団体が策定しています。

OpenCTIのデータモデルはSTIX 2.1に基づいています。つまり、OpenCTIに入っているすべてのデータは、最終的にSTIX 2.1のオブジェクトとして表現されます。

## 3.2 なぜSTIXが重要か

STIXが重要な理由は「相互運用性」です。

例えるなら、STIXは脅威インテリジェンスの世界における「JSON」のようなものです。REST APIがJSONという共通フォーマットを使うことで異なるシステムがデータをやり取りできるように、STIXという共通フォーマットを使うことで異なるCTIプラットフォーム間でデータを共有できます。

## 3.3 STIX 2.1の主要オブジェクト

STIX 2.1には18種類のSDO（STIX Domain Object）と2種類のSRO（STIX Relationship Object）が定義されています。OpenCTIでよく使うものを紹介します。

**SDO（ドメインオブジェクト）— 「モノ」を表す**

| オブジェクト | 説明 | OpenCTIのセクション |
|-------------|------|-------------------|
| `threat-actor` | 攻撃者（個人・グループ） | Threats |
| `intrusion-set` | 攻撃グループの行動パターン | Threats |
| `campaign` | 一連の攻撃活動 | Threats |
| `malware` | マルウェア | Arsenal |
| `tool` | 攻撃に使われるツール | Arsenal |
| `vulnerability` | 脆弱性（CVE） | Arsenal |
| `attack-pattern` | 攻撃手法（MITRE ATT&CK） | Techniques |
| `indicator` | IOC（侵害指標） | Observations |
| `report` | 脅威レポート | Analyses |
| `identity` | 組織・個人・セクター | Entities |
| `location` | 国・地域 | Entities |

**SRO（リレーションシップオブジェクト）— 「つながり」を表す**

| オブジェクト | 説明 |
|-------------|------|
| `relationship` | 2つのオブジェクト間の関連（例: マルウェアAは脅威アクターBが「使用する」） |
| `sighting` | あるIndicatorが特定の場所で「目撃された」ことを表す |

## 3.4 Relationship（関連性）の例

STIXの真価はオブジェクト単体ではなく、それらの「関連性」にあります。

```
[Lazarus Group] --uses--> [WannaCry]
     |                        |
     |--targets-->            |--exploits-->
     |                        |
[Financial Sector]     [CVE-2017-0144]
     |                        |
     |                   [EternalBlue]
     |                        |
     └--attributed-to--> [North Korea]
```

この例では、北朝鮮に帰属するLazarus Groupが金融セクターを標的にし、WannaCryマルウェアを使用し、そのマルウェアはCVE-2017-0144（EternalBlue）を悪用する、という一連の関連性が表現されています。

OpenCTIはこうした関連性をグラフDBとして保持し、画面上で探索できるようにしています。

## 3.5 TLP（Traffic Light Protocol）

OpenCTIの各データには「Marking」として TLP（Traffic Light Protocol）が付与されることがあります。これは情報の共有範囲を示すラベルです。

| TLP | 意味 |
|-----|------|
| **TLP:CLEAR** | 制限なし。公開可能 |
| **TLP:GREEN** | コミュニティ内で共有可 |
| **TLP:AMBER** | 組織内で共有可（Need-to-know） |
| **TLP:AMBER+STRICT** | 組織内の限定メンバーのみ |
| **TLP:RED** | 受信者のみ。転送禁止 |

デモ環境のReports一覧で各レポートの右端に「TLP:CLEAR」と表示されているのがこれです。

---

## 3.6 Threatsセクションの構成

左サイドバーの「Threats」をクリックすると、以下のサブセクションが表示されます。

- **Threat Actors (Group)**: 攻撃者グループ（APT28、Lazarus Groupなど）
- **Threat Actors (Individual)**: 個人の攻撃者
- **Intrusion Sets**: 攻撃行動パターンのグルーピング
- **Campaigns**: 特定目的の攻撃キャンペーン

## 3.7 Intrusion Sets

> **確認方法**: https://demo.opencti.io/dashboard/threats/intrusion_sets
> <!-- スクリーンショット: Intrusion Sets一覧 -->

デモ環境には1,310件以上のIntrusion Setが登録されています。カード表示では各Intrusion Setについて以下の情報が一覧できます。

- **名前**: Oktapus、1877 team、8220 Gang、A41APT など
- **使用マルウェア**: 例えばA41APTは「P8RAT, QuasarRAT - S0262, DILLJUICE, FYAnti」を使用
- **標的国**: 例えば8220 Gangは「Brazil, China」を標的
- **標的セクター**: 例えばOktapusは「Finance, Telecommunications, Technologies」を標的

## 3.8 Intrusion Setの詳細ページ

任意のIntrusion Setをクリックすると、詳細ページに遷移します。ここでは以下の情報が確認できます。

**Overview（概要）**: 説明文、別名（Aliases）、起源国、最初の活動確認日、最終活動確認日、信頼度レベルなど。

**Knowledge（ナレッジ）**: そのIntrusion Setに関連するすべてのエンティティとの関連性をグラフやリストで確認できます。「どのマルウェアを使うか」「どの脆弱性を悪用するか」「どの国を標的にするか」などが視覚的に分かります。

**Analyses（分析）**: 関連するレポートやノートの一覧。

**Indicators（指標）**: そのIntrusion Setに紐づくIOC（IPアドレス、ドメイン、ハッシュ値など）。

## 3.9 Threat ActorとIntrusion Setの違い

この2つの違いは初見では分かりにくいですが、重要な概念上の区別があります。

**Threat Actor**: 「誰が」に焦点を当てた概念。組織としての攻撃者グループそのものを指します。政治的動機、組織構造、帰属国などの情報が中心です。

**Intrusion Set**: 「何をするか」に焦点を当てた概念。特定の攻撃者に紐づく一連の行動パターン（使用するツール、攻撃手法、インフラ）をグループ化したものです。

1つのThreat Actorが複数のIntrusion Setを持つことがあります。例えば、ある国家支援グループが「スパイ活動用のIntrusion Set」と「金銭目的のIntrusion Set」を別々に運用しているケースです。

---

## 3.10 Arsenalセクションの構成

「Arsenal」は攻撃者が使用するツール・武器をまとめたセクションです。

- **Malware**: マルウェア
- **Channels**: 攻撃者が使用する通信チャネル
- **Tools**: 正規ツールの悪用（Mimikatz、Cobalt Strikeなど）
- **Vulnerabilities**: 脆弱性（CVE）

## 3.11 Malware

> **確認方法**: https://demo.opencti.io/dashboard/arsenal/malwares

<!-- スクリーンショット: Malware -->

デモ環境には5,310件以上のマルウェアが登録されています。

カード表示では各マルウェアについて以下が分かります。

- **名前**: Mimikatz、Meterpreter、3AM、3PARA RATなど
- **関連Intrusion Set**: どの攻撃グループが使用しているか
- **標的国**: どの国で観測されたか
- **標的セクター**: どの業種が狙われているか

## 3.12 Vulnerabilities

> **確認方法**: https://demo.opencti.io/dashboard/arsenal/vulnerabilities

<!-- スクリーンショット: Vulnerabilities -->

デモ環境には195,350件以上の脆弱性が登録されています。リスト表示では以下のカラムが確認できます。

- **Name**: CVE番号（CVE-2025-55182、CVE-2025-24893など）
- **CVSS3 - Severity**: 深刻度（CRITICAL / HIGH / MEDIUM / LOW）
- **Labels**: 分類タグ
- **Original creation date**: CVE公開日
- **Modification date**: 最終更新日

CVSSスコアが色分けされているため、CRITICAL（赤）やHIGH（オレンジ）の脆弱性を視覚的にすばやく識別できます。

## 3.13 ToolsとMalwareの違い

**Malware**: 攻撃目的で作られた悪意のあるソフトウェア。ランサムウェア、トロイの木馬、ワームなど。

**Tool**: 本来は正規の目的で作られたソフトウェアだが、攻撃者にも悪用されるもの。例えばMimikatz（認証情報抽出）、PsExec（リモート実行）、Cobalt Strike（ペネトレーションテスト）など。

この区別が重要な理由は、検知アプローチが異なるためです。Malwareはシグネチャで検知しやすいですが、正規Toolsはホワイトリストされていることが多く、検知が難しい傾向があります。

---

## 3.14 Observationsセクションの構成

「Observations」は実際に観測された技術的な情報を扱うセクションです。

- **Indicators**: IOC（侵害指標）— STIXパターンで記述
- **Observables**: 観測された具体的な値（IPアドレス、ドメイン、ハッシュ値など）
- **Artifacts**: 実際のファイルやサンプル

## 3.15 Indicators（IOC）

> **確認方法**: https://demo.opencti.io/dashboard/observations/indicators

<!-- スクリーンショット: Indicators -->

デモ環境には668,710件以上のIndicatorが登録されています。リスト表示のカラムは以下の通りです。

- **Pattern type**: パターンの種類（ほとんどが「Stix」）
- **Name**: 具体的な値（URL、IPアドレスなど）
- **Author**: 情報提供元
- **Labels**: 分類タグ（Mirai、Mozi、Clearfakeなど）
- **Original creation date**: 作成日時
- **Marking**: TLPレベル

## 3.16 IndicatorとObservableの違い

この2つの違いは重要です。

**Observable（SCO: STIX Cyber-observable Object）**: 単なる「観測された事実」。「IPアドレス 192.168.1.1 が観測された」という価値判断のない事実です。

**Indicator（SDO: STIX Domain Object）**: 「このパターンに合致する通信があったら、侵害されている可能性がある」という判断が入った情報。有効期限（Valid until）があり、時間とともに価値が変わります。

例えるなら、Observableは「指紋」、Indicatorは「指名手配書」です。指紋そのものに善悪はありませんが、指名手配書は「この指紋の持ち主は危険」という判断を含んでいます。

## 3.17 IOCの具体例

デモ環境のIndicatorリストを見ると、以下のようなIOCが登録されていることが分かります。

- `http://42.224.124.46:60213/bin.sh` — マルウェアのダウンロードURL（Mozi関連）
- `http://61.54.253.143:42587/i` — C2通信先
- `https://uf0t.scrollnft.in.net/verification.google` — フィッシングURL（Clearfake関連）

ラベルに「Mirai」「Mozi」「Clearfake」などがついており、どのマルウェアファミリーに関連するIOCかが分かるようになっています。

## 3.18 IOCの活用シーン

IOCは以下のような形で活用されます。

**SIEM/SOARへの連携**: OpenCTIからIOCをエクスポートし、SIEMのルールに組み込むことで、社内ネットワークで不審な通信を自動検知できます。

**ファイアウォール/プロキシのブロックリスト**: 悪意のあるIPアドレスやドメインをブロックリストとして配信し、予防的に遮断します。

**インシデント調査**: インシデント発生時に、観測されたIOCをOpenCTIで検索し、関連する脅威アクターや攻撃キャンペーンを素早く特定します。
