# supabase/ について(重要: migration の取り扱い)

## 現在の状態

`supabase/migrations/` にある次の6本のSQLは、**すでに本番DBへ適用済み**です。

| ファイル | 内容 |
|---|---|
| `20261009120000_step1_shortstay_auth_foundation.sql` | 職員認証の基盤(認証用テーブル3つ・内部関数) |
| `20261009130000_step2_shortstay_entry_rpcs.sql` | 利用者データ用RPC(一覧・追加更新・削除・全件削除) |
| `20261009140000_step3_pin_policy.sql` | パスワード仕様の変更 |
| `20261009150000_step4_staff_lock_hardening.sql` | 職員のロック強化 |
| `20261009160000_step5_password_4digit.sql` | 職員・管理者とも4桁の数字に統一 |
| `20261009170000_step6_admin_reauth_and_session.sql` | 全件削除時の管理者パスワード再入力、管理者セッション2時間 |

- 適用方法は `supabase db query --linked -f <ファイル>` です。
- **Supabaseのmigration履歴(`supabase_migrations.schema_migrations`)には登録していません。**
- 本番側にだけ存在するmigration履歴があり、ローカルの `supabase/migrations/` と一致しません。

## 禁止事項

- **`supabase db push` を実行しないでください。**
  - この6本は適用済みのため、再適用されると失敗します(`CREATE FUNCTION` / `CREATE TABLE` が既存と衝突します)。
  - 履歴の不整合でも停止します。
  - 途中まで適用された場合、本番の認証設定を壊すおそれがあります。
- この6本を、そのまま別のDB(開発用・新規プロジェクト)へ流用しないでください。順番・前提(工程1→6、既存の `shortstay_entries`)に依存します。
- `supabase migration repair` などで履歴を書き換えないでください。

## migration履歴を整理したい場合

履歴の整理(ローカルと本番の履歴の統一、repair、`db pull` など)は、**別の作業として慎重に**行ってください。

- 事前に本番の完全バックアップを取り、手順と戻し方を決めてから実施してください。
- 実行前に、本番で現在どの関数・テーブルが存在するかを読み取り専用で確認してください。
- 秘密情報・接続情報は、このリポジトリに記録しないでください。

## 関連ファイル

- `tools/set_shortstay_pin.py`: ログイン用パスワードの設定・変更ツール(手動実行用)。
- `shortstay_calendar_v14_secure.html`: PIN認証とRPCを使う新版。
