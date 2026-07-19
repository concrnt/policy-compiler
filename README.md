# concrnt-policy-compiler

[Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) のサブセットで書いたポリシーを、concrnt のカスタムJSONポリシー形式(バージョン `2025-12-23`)にコンパイルするツールです。

JSONの式ツリー(`{"op": "And", "args": [...]}`)を直接書く代わりに、人間に読みやすいRegoでポリシーを記述できます。

```rego
# METADATA
# title: restrict-readers
package restrict_readers

deny if {
    input.action == "record:read"
    key_matches("./*")
    not input.requester.ccid in input.params.entities
}
```

↓ コンパイル

```json
{
  "name": "restrict-readers",
  "versions": {
    "2025-12-23": {
      "statements": [
        {
          "action": "record:read",
          "key": "./*",
          "emit": "deny",
          "condition": {
            "op": "Not",
            "args": [
              {"op": "Contains", "args": [
                {"op": "Load", "const": "params.entities"},
                {"op": "Load", "const": "requester.ccid"}
              ]}
            ]
          }
        }
      ]
    }
  }
}
```

## 使い方

```sh
# ビルド(.regoファイルまたはディレクトリを指定、<name>.json を出力)
concrnt-policy-compiler build -o dist/ policies/

# 単一ファイルを標準出力へ
concrnt-policy-compiler build --stdout policies/whisper.rego

# 検証のみ(CI向け、エラーがあれば非0終了)
concrnt-policy-compiler check policies/
```

## ポリシーの書き方

1つの `.rego` ファイルが1つのポリシードキュメントになります。

### statement: `allow` / `deny` / `ok` / `ng` ルール

**ルール名がそのままemit**になります。この4つの名前のルールだけがstatementを生成し、**ルール定義1つがstatement 1つ**に対応します(同じ名前で何個でも定義できます)。

```rego
deny contains "DENY: you are not a participant" if {
    input.action == "record:read"    # 必須: このstatementが対象とするaction
    key_matches("./*")               # 必須: 対象keyのパターン
    not can_read                     # 残りが条件式になる
}
```

- **action**: `input.action == "record:read"` のリテラルで指定します(必須・1個)。コンパイル時に `Statement.Action` に抽出され、条件式には残りません。
- **key**: `key_matches("<pattern>")` で指定します(必須)。パターンは `.`(アタッチ先自身)、`./*`(子孫のみ)、`""` または `*`(自身と子孫)。concrntエンジンは `*` をワイルドカードとして解釈します。全keyに適用するなら `key_matches("*")` と明示します。
- **reason** は3通り:

```rego
# 1. headに直接書く
deny contains "not in the reader list" if { ... }

# 2. bodyで変数を文字列定数に束縛する(長いreasonでheadを読みやすく保ちたいとき)
deny contains reason if {
    ...
    reason := "not in the reader list"
}

# 3. reasonなし
deny if { ... }
```

条件がaction/keyの指定だけのstatement(無条件)は、条件 `{"op": "Const", "const": true}` にコンパイルされます。

### 補助ルール

allow/deny/ok/ng 以外の名前のルールは補助ルールです。statementから参照すると**インライン展開**されます。同名の複数定義は **Or**、body内の複数リテラルは **And** になります。

```rego
can_read if input.self.author == input.requester.ccid
can_read if input.requester.ccid in input.params.participants
```

補助ルールに `contains` は使えません。また、statementルールを条件から参照することはできません(共有ロジックは補助ルールに切り出してください)。

### defaults

actionごとのデフォルト結論は、予約名 `defaults` のルールで宣言します。

```rego
defaults := {
    "record:create": "ng",
    "record:read": "ok",
}
```

### ドキュメントのメタ情報(packageのMETADATA)

name / description / paramSchema は package 直前のMETADATAで指定します。

```rego
# METADATA
# title: whisper                          # ドキュメントのname(省略時: package名の _ → -)
# description: 参加者だけが読めるポリシー   # description(省略可)
# custom:
#   version: "2025-12-23"                 # 省略可(既定値)。これ以外はエラー
#   paramSchema:                          # JSON SchemaをYAMLで記述、そのまま出力される(省略可)
#     type: object
#     properties:
#       participants:
#         type: array
#         items: {type: string}
#     required: [participants]
#     ui:
#       participants: {"ui:widget": userPicker}
package whisper
```

### 式のサポート範囲

concrntのポリシーエンジンは8つのオペレータ(`And` `Or` `Not` `Eq` `Contains` `CCUriOwner` `Load` `Const`)しか持たないため、条件式もそれに対応するサブセットのみ使えます。

| Rego | concrnt |
|---|---|
| `input.requester.ccid` | `Load "requester.ccid"` |
| `x == y` / `x != y` | `Eq` / `Not(Eq)` |
| `x in list` | `Contains(list, x)` |
| `not <式>` | `Not` |
| `ccuri_owner(x)` | `CCUriOwner`(CCURIから所有者IDを取り出す) |
| `concrnt_call(resolver, api, k1, v1, ...)` | `ConcrntCall`(named APIの呼び出し。例: `"net.concrnt.core.acknowledges"`。key/valueペアで引数を渡す) |
| `is_not_empty(x)` | `IsNotEmpty`(配列/文字列/マップが空でないか) |
| `true` / `"str"` / `1.5` / `["a", "b"]` | `Const` |

`input` のルートは `requester` `requester_domain` `parent` `self` `params` `globals`(+statement body直下のみ `action` と `key_matches`)です。

**使えないもの**(位置情報つきのコンパイルエラーになります): 算術・大小比較、`=`(ユニフィケーション)、`:=`(reason束縛を除く)、内包表記、`every` / `some`、イテレーション(`xs[_]`)、`with`、`else`、`default`ルール、値付きルール、関数定義、object/setリテラル、文字列系ビルトイン全般、`import`。

## 開発

```sh
go build ./...
go test ./...
```

- `examples/` — [world-policies](https://github.com/concrnt/world-policies) の新形式ポリシーと concrnt 本体のグローバルポリシーをRegoで書き直したもの
- `testdata/golden/` — examples に対応する期待JSON。テストで意味比較(キー順無視)される
- `roundtrip_test.go` — コンパイル結果を concrnt 本体の `policy.EvaluatePolicy` で実評価し、既存実装と同じ結論になることを検証(`go.mod` の `replace` で `../concrnt` を参照)

## 既知の注意点

- world-policies の `private.json` は条件を `{"const": true}`(`op` なし)と書いていますが、この形はconcrntエンジンでは unknown operator エラーになり statement が発火しません。本コンパイラは常に動作する `{"op": "Const", "const": true}` を出力します。
- YAML経由のparamSchemaでは整数も float64 として扱われますが、JSON Schema用途では実害ありません。
