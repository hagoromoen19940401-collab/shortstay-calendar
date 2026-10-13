-- 工程6: 全件削除の再認証 + 管理者セッションを2時間に短縮
--
--   1. ss_delete_all_entries に管理者パスワードの再入力を必須化(サーバー側で検証してから削除)。
--      旧シグネチャ ss_delete_all_entries(text,text) は同一トランザクション内で DROP する
--      (残すと、パスワードなしで全件削除できてしまうため)。
--      再入力の失敗は、ログインと同じ管理者の失敗カウンタ・ロック(5回→30分)に加算する。
--      (加算しないと、奪われた管理者セッションからロックなしで総当たりできるため)
--   2. 管理者セッションの有効期間を2時間にする(職員は12時間のまま)。
--
-- 検証ロジック(失敗回数・ロック)は内部関数 ss_verify_password に集約し、ss_login も使う。
-- 失敗は例外にせず jsonb で返す(例外にすると失敗回数の更新がロールバックされるため)。
--
-- 対象: 関数の追加・置き換えのみ。shortstay_entries の定義・データ・RLS・policy(allow_all)・GRANT、
--       認証3テーブル、他の関数は変更しない。パスワード(平文)は保存もログ出力もしない。
-- SECURITY DEFINER / search_path = pg_catalog, pg_temp / 完全修飾 / REVOKE→明示GRANT は維持。

BEGIN;

DO $$
BEGIN
  IF to_regprocedure('public.ss_login(text,text)') IS NULL
     OR to_regprocedure('public.ss_require_session(text,text)') IS NULL
     OR to_regprocedure('public.ss_delete_all_entries(text,text)') IS NULL THEN
    RAISE EXCEPTION 'previous steps are not installed as expected';
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 1. パスワード検証 + 失敗回数/ロック管理(内部関数。外部から実行不可)
--    成功: {"ok":true}
--    失敗: {"ok":false,"error":"invalid_pin"} / {"ok":false,"error":"locked","locked_until":...}
--          / {"ok":false,"error":"invalid_role"}(DB は書き換えない)
--    制限: staff / admin とも 15分の窓で5回失敗 → 30分ロック(role 別)。
-- ---------------------------------------------------------------------------
CREATE FUNCTION public.ss_verify_password(p_role text, p_password text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  c_window     constant interval := interval '15 minutes';
  c_lock       constant interval := interval '30 minutes';
  c_max        constant integer  := 5;
  v_now        timestamptz := pg_catalog.now();
  v_att        public.shortstay_auth_attempts%ROWTYPE;
  v_ok         boolean := false;
  v_failed     integer;
  v_window     timestamptz;
  v_locked     timestamptz;
BEGIN
  IF p_role IS NULL OR p_role NOT IN ('staff', 'admin') THEN
    RETURN pg_catalog.jsonb_build_object('ok', false, 'error', 'invalid_role');
  END IF;

  INSERT INTO public.shortstay_auth_attempts (scope) VALUES (p_role)
  ON CONFLICT (scope) DO NOTHING;

  SELECT * INTO v_att
  FROM public.shortstay_auth_attempts WHERE scope = p_role FOR UPDATE;

  IF v_att.locked_until IS NOT NULL AND v_att.locked_until > v_now THEN
    RETURN pg_catalog.jsonb_build_object('ok', false, 'error', 'locked',
                                         'locked_until', v_att.locked_until);
  END IF;

  IF p_password IS NOT NULL AND p_password ~ '^[0-9]{4}$' THEN
    SELECT true INTO v_ok
    FROM public.shortstay_auth a
    WHERE a.role = p_role
      AND a.pin_hash = extensions.crypt(p_password, a.pin_hash);
    v_ok := COALESCE(v_ok, false);
  END IF;

  IF NOT v_ok THEN
    IF v_att.window_started_at < v_now - c_window THEN
      v_failed := 1;
      v_window := v_now;
    ELSE
      v_failed := v_att.failed_count + 1;
      v_window := v_att.window_started_at;
    END IF;
    v_locked := NULL;
    IF v_failed >= c_max THEN
      v_locked := v_now + c_lock;
      v_failed := 0;
      v_window := v_now;
    END IF;
    UPDATE public.shortstay_auth_attempts
    SET failed_count = v_failed, window_started_at = v_window, locked_until = v_locked
    WHERE scope = p_role;
    RETURN pg_catalog.jsonb_build_object('ok', false, 'error', 'invalid_pin');
  END IF;

  UPDATE public.shortstay_auth_attempts
  SET failed_count = 0, window_started_at = v_now, locked_until = NULL
  WHERE scope = p_role;

  RETURN pg_catalog.jsonb_build_object('ok', true);
END;
$$;
REVOKE ALL ON FUNCTION public.ss_verify_password(text, text) FROM PUBLIC, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 2. ログイン(置き換え)。検証は ss_verify_password に委譲。
--    セッション有効期間: admin = 2時間 / staff = 12時間。
--    成功: {"ok":true,"token":...,"role":...,"expires_at":...}
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.ss_login(p_role text, p_pin text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now     timestamptz := pg_catalog.now();
  v_res     pg_catalog.jsonb;
  v_token   text;
  v_expires timestamptz;
BEGIN
  v_res := public.ss_verify_password(p_role, p_pin);
  IF NOT (v_res->>'ok')::boolean THEN
    RETURN v_res;
  END IF;

  DELETE FROM public.shortstay_sessions WHERE expires_at <= v_now;

  v_token   := pg_catalog.encode(extensions.gen_random_bytes(32), 'hex');
  v_expires := v_now + CASE WHEN p_role = 'admin' THEN interval '2 hours' ELSE interval '12 hours' END;
  INSERT INTO public.shortstay_sessions (token_hash, role, expires_at)
  VALUES (public.ss_hash_token(v_token), p_role, v_expires);

  RETURN pg_catalog.jsonb_build_object('ok', true, 'token', v_token,
                                       'role', p_role, 'expires_at', v_expires);
END;
$$;
REVOKE ALL ON FUNCTION public.ss_login(text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ss_login(text, text) TO anon;

-- ---------------------------------------------------------------------------
-- 3. 全件削除(再認証つき)。順序:
--      管理者セッション確認(staff は forbidden) → 確認文字列 → 管理者パスワード検証 → 削除
--    成功: {"ok":true,"deleted":N}
--    パスワード不一致/ロック中: {"ok":false,"error":"invalid_pin"|"locked",...}(削除しない)
-- ---------------------------------------------------------------------------
CREATE FUNCTION public.ss_delete_all_entries(p_token text, p_confirm text, p_password text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_res     pg_catalog.jsonb;
  v_deleted integer;
BEGIN
  PERFORM public.ss_require_session(p_token, 'admin');

  IF p_confirm IS DISTINCT FROM 'DELETE_ALL_SHORTSTAY_ENTRIES' THEN
    RAISE EXCEPTION 'confirmation text mismatch' USING ERRCODE = '22023';
  END IF;

  v_res := public.ss_verify_password('admin', p_password);
  IF NOT (v_res->>'ok')::boolean THEN
    RETURN v_res;
  END IF;

  DELETE FROM public.shortstay_entries WHERE true;
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN pg_catalog.jsonb_build_object('ok', true, 'deleted', v_deleted);
END;
$$;
REVOKE ALL ON FUNCTION public.ss_delete_all_entries(text, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ss_delete_all_entries(text, text, text) TO anon;

-- 旧シグネチャ(パスワードなしで全件削除できる版)を削除
DROP FUNCTION public.ss_delete_all_entries(text, text);

-- ---------------------------------------------------------------------------
-- 4. 自己検証(不一致なら例外 → 全体ロールバック)
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  r       record;
  v_oid   oid;
  v_proc  pg_proc%ROWTYPE;
  v_count integer;
  v_src   text;
BEGIN
  FOR r IN
    SELECT * FROM (VALUES
      ('public.ss_hash_token(text)',                   false, false),
      ('public.ss_require_session(text,text)',         false, true),
      ('public.ss_set_pin(text,text)',                 false, true),
      ('public.ss_reset_attempts(text)',               false, true),
      ('public.ss_verify_password(text,text)',         false, true),
      ('public.ss_login(text,text)',                   true,  true),
      ('public.ss_logout(text)',                       true,  true),
      ('public.ss_list_entries(text)',                 true,  true),
      ('public.ss_upsert_entry(text,jsonb)',           true,  true),
      ('public.ss_delete_entry(text,uuid)',            true,  true),
      ('public.ss_delete_all_entries(text,text,text)', true,  true)
    ) AS v(sig, anon_exec, secdef)
  LOOP
    v_oid := to_regprocedure(r.sig);
    IF v_oid IS NULL THEN RAISE EXCEPTION 'function % not found', r.sig; END IF;
    SELECT * INTO v_proc FROM pg_proc WHERE oid = v_oid;
    IF v_proc.prosecdef <> r.secdef THEN RAISE EXCEPTION 'unexpected SECURITY DEFINER state on %', r.sig; END IF;
    IF NOT EXISTS (SELECT 1 FROM unnest(v_proc.proconfig) c WHERE replace(c, ' ', '') = 'search_path=pg_catalog,pg_temp') THEN
      RAISE EXCEPTION 'search_path is not pinned on %', r.sig;
    END IF;
    IF has_function_privilege('anon', v_oid, 'EXECUTE') <> r.anon_exec THEN RAISE EXCEPTION 'unexpected anon EXECUTE state on %', r.sig; END IF;
    IF has_function_privilege('authenticated', v_oid, 'EXECUTE') THEN RAISE EXCEPTION 'authenticated can execute %', r.sig; END IF;
    IF v_proc.proacl IS NULL
       OR EXISTS (SELECT 1 FROM aclexplode(v_proc.proacl) x WHERE x.grantee = 0 AND x.privilege_type = 'EXECUTE') THEN
      RAISE EXCEPTION 'PUBLIC can execute %', r.sig;
    END IF;
  END LOOP;

  -- ss_* 関数はちょうど11個(旧 ss_delete_all_entries(text,text) が残っていないこと)
  SELECT count(*) INTO v_count FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'ss\_%';
  IF v_count <> 11 THEN RAISE EXCEPTION 'expected 11 ss_* functions in public, found %', v_count; END IF;
  IF to_regprocedure('public.ss_delete_all_entries(text,text)') IS NOT NULL THEN
    RAISE EXCEPTION 'old ss_delete_all_entries(text,text) still exists';
  END IF;

  -- 仕様の反映
  SELECT prosrc INTO v_src FROM pg_proc WHERE oid = 'public.ss_login(text,text)'::regprocedure;
  IF position('interval ''2 hours''' in v_src) = 0 OR position('interval ''12 hours''' in v_src) = 0
     OR position('ss_verify_password' in v_src) = 0 THEN
    RAISE EXCEPTION 'session policy not reflected in ss_login';
  END IF;
  SELECT prosrc INTO v_src FROM pg_proc WHERE oid = 'public.ss_delete_all_entries(text,text,text)'::regprocedure;
  IF position('ss_verify_password(''admin'', p_password)' in v_src) = 0
     OR position('ss_require_session(p_token, ''admin'')' in v_src) = 0 THEN
    RAISE EXCEPTION 're-authentication not reflected in ss_delete_all_entries';
  END IF;
  SELECT prosrc INTO v_src FROM pg_proc WHERE oid = 'public.ss_verify_password(text,text)'::regprocedure;
  IF position('c_max        constant integer  := 5;' in v_src) = 0
     OR position('interval ''30 minutes''' in v_src) = 0
     OR position('^[0-9]{4}$' in v_src) = 0 THEN
    RAISE EXCEPTION 'lock settings not reflected in ss_verify_password';
  END IF;
END $$;

COMMIT;

-- ---------------------------------------------------------------------------
-- ロールバック(この工程を取り消す場合。旧 ss_delete_all_entries(text,text) は工程2の定義で再作成が必要):
--   工程5の ss_login と、工程2の ss_delete_all_entries(text,text) を再実行し、
--   DROP FUNCTION public.ss_delete_all_entries(text,text,text); DROP FUNCTION public.ss_verify_password(text,text);
-- ---------------------------------------------------------------------------
