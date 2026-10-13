#!/usr/bin/env python3
"""ショートステイ ログイン用パスワードの設定・変更ツール(手動実行用)。

使い方(プロジェクトのルートで):
    tools/.venv/bin/python tools/set_shortstay_pin.py staff
    tools/.venv/bin/python tools/set_shortstay_pin.py admin

- パスワードは画面に表示されず、コマンド履歴・SQL・ログ・Git に残らない。
- パスワードは手元で bcrypt ハッシュ化し、ハッシュだけを linked 本番DBへ書き込む。
  ハッシュも画面・エラー表示には出さない(4桁は、ハッシュから総当たりで復元できてしまうため)。
- 職員(staff)・管理者(admin)とも、4桁の数字。職員と管理者は同じパスワードにできない。
- 変更したroleの既存ログイン(セッション)は失効し、ロック/失敗回数もリセットされる。
"""
import getpass
import json
import os
import re
import subprocess
import sys
import tempfile

import bcrypt

ROLES = ("staff", "admin")
NAMES = {"staff": "職員", "admin": "管理者"}
# --agent no --output-format json: 呼び出し元がAIエージェントかどうかに関わらず、
# 出力が「行の配列」(例: [] / [{"col": 1}])に固定される。
CLI = ["npx", "--yes", "supabase@latest", "db", "query", "--linked",
       "--agent", "no", "--output-format", "json"]
HASH_RE = re.compile(r"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}")


def redact(text):
    """エラー表示用: bcryptハッシュを伏せる。"""
    return HASH_RE.sub("[hash]", text or "")


def parse_rows(stdout):
    """CLIの標準出力(JSON全体)から行の配列を取り出す。文字列検索はしない。
    想定する形: 配列 [...] / (旧形式)オブジェクト {"rows": [...]}。"""
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except ValueError:
        raise RuntimeError("CLIの出力をJSONとして解釈できませんでした。")
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("rows"), list):
        return data["rows"]
    raise RuntimeError("CLIの出力形式が想定外です。")


def run_sql(sql, as_file=False):
    path = None
    try:
        if as_file:
            fd, path = tempfile.mkstemp(suffix=".sql")
            os.chmod(path, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(sql)
            args = CLI + ["-f", path]
        else:
            args = CLI + [sql]
        p = subprocess.run(args, capture_output=True, text=True)
    finally:
        if path and os.path.exists(path):
            os.remove(path)
    if p.returncode != 0:
        msg = redact((p.stderr or p.stdout or "").strip())[-400:]
        sys.exit("DB実行に失敗しました:\n" + msg)
    try:
        return parse_rows(p.stdout)
    except RuntimeError as e:
        sys.exit(f"{e} (CLIは正常終了しました。DBの変更有無は、設定後の確認でご確認ください)")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ROLES:
        sys.exit("使い方: set_shortstay_pin.py staff|admin")
    role = sys.argv[1]
    other = "admin" if role == "staff" else "staff"
    name, other_name = NAMES[role], NAMES[other]

    pw = getpass.getpass(f"{name}の新しいパスワード(4桁の数字): ")
    if not re.fullmatch(r"[0-9]{4}", pw):
        sys.exit(f"{name}のパスワードは4桁の数字にしてください。")
    if len(set(pw)) == 1 or pw in "01234567890123456789" or pw in "98765432109876543210":
        sys.exit("同じ数字の連続・連番は使えません。")
    if getpass.getpass("もう一度入力: ") != pw:
        sys.exit("一致しません。中止しました。")

    rows = run_sql(f"select pin_hash from public.shortstay_auth where role = '{other}'")
    if rows and bcrypt.checkpw(pw.encode(), rows[0]["pin_hash"].encode()):
        sys.exit(f"{other_name}と同じパスワードは設定できません。")

    h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(10, prefix=b"2a")).decode()
    del pw
    assert HASH_RE.fullmatch(h)
    sql = f"""BEGIN;
INSERT INTO public.shortstay_auth (role, pin_hash, updated_at)
VALUES ('{role}', '{h}', now())
ON CONFLICT (role) DO UPDATE SET pin_hash = EXCLUDED.pin_hash, updated_at = EXCLUDED.updated_at;
DELETE FROM public.shortstay_sessions WHERE role = '{role}';
UPDATE public.shortstay_auth_attempts SET failed_count = 0, window_started_at = now(), locked_until = NULL WHERE scope = '{role}';
COMMIT;
"""
    run_sql(sql, as_file=True)

    # 書き込み結果の確認(ハッシュは取得・表示しない)
    chk = run_sql(f"select count(*) as n from public.shortstay_auth where role = '{role}'")
    if not chk or int(chk[0]["n"]) != 1:
        sys.exit("設定の確認に失敗しました。もう一度実行してください。")
    print(f"{name}のパスワードを設定しました。(既存のログインは失効、ロックは解除)")


if __name__ == "__main__":
    main()
