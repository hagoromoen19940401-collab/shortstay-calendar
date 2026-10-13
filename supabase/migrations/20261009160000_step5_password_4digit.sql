-- 工程5: パスワード仕様の変更(関数の置き換えのみ。テーブル・データ・権限設計は変更しない)
--
--   職員(staff) : 数字4桁固定
--   管理者(admin): 数字4桁固定            (変更: 旧 8桁以上)
--   職員と管理者は同じパスワードを使えない(ss_set_pin で検証。4桁同士なので実際に衝突し得る)
--   ロック: staff / admin ともに 15分の窓で5回失敗 → 30分ロック(role 別。変更なし)
--
-- 対象: ss_set_pin(text,text) / ss_login(text,text) の置き換え(CREATE OR REPLACE)。
-- 対象外: shortstay_entries、allow_all、既存GRANT、認証3テーブル、他の関数、セッション方式。
-- SECURITY DEFINER / search_path = pg_catalog, pg_temp / 完全修飾は維持。置き換え後に REVOKE→GRANT をやり直し、
-- 末尾で全10関数の権限を自己検証する。
-- 注意: 管理者の4桁化により、管理者権限(全件削除など)の総当たり耐性は下がる。
--       全件削除は引き続き「管理者トークン + 確認文字列」の両方が必要。

BEGIN;

DO $$
BEGIN
  IF to_regprocedure('public.ss_set_pin(text,text)') IS NULL
     OR to_regprocedure('public.ss_login(text,text)') IS NULL THEN
    RAISE EXCEPTION 'step1 functions are not installed';
  END IF;
  -- 既存のパスワードが設定済みなら、新仕様と矛盾しないか(4桁以外のハッシュは再設定が必要)
  -- ハッシュからは桁数が分からないため、設定済みの場合は中止して再設定を促す。
  IF EXISTS (SELECT 1 FROM public.shortstay_auth) THEN
    RAISE EXCEPTION 'shortstay_auth already has rows: reset passwords with the tool after applying, then re-run';
  END IF;
END $$;

CREATE OR REPLACE FUNCTION public.ss_set_pin(p_role text, p_pin text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF p_role IS NULL OR p_role NOT IN ('staff', 'admin') THEN
    RAISE EXCEPTION 'invalid role' USING ERRCODE = '22023';
  END IF;

  IF p_pin IS NULL OR p_pin !~ '^[0-9]{4}$' THEN
    RAISE EXCEPTION 'password must be exactly 4 digits' USING ERRCODE = '22023';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.shortstay_auth a
    WHERE a.role <> p_role
      AND a.pin_hash = extensions.crypt(p_pin, a.pin_hash)
  ) THEN
    RAISE EXCEPTION 'password must differ between roles' USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.shortstay_auth (role, pin_hash, updated_at)
  VALUES (p_role, extensions.crypt(p_pin, extensions.gen_salt('bf', 10)), pg_catalog.now())
  ON CONFLICT (role) DO UPDATE
    SET pin_hash = EXCLUDED.pin_hash, updated_at = EXCLUDED.updated_at;

  DELETE FROM public.shortstay_sessions WHERE role = p_role;

  UPDATE public.shortstay_auth_attempts
  SET failed_count = 0, window_started_at = pg_catalog.now(), locked_until = NULL
  WHERE scope = p_role;
END;
$$;

CREATE OR REPLACE FUNCTION public.ss_login(p_role text, p_pin text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  c_window  constant interval := interval '15 minutes';
  c_session constant interval := interval '12 hours';
  v_max     integer;
  v_pattern text;
  v_lock    interval;
  v_now     timestamptz := pg_catalog.now();
  v_att     public.shortstay_auth_attempts%ROWTYPE;
  v_ok      boolean := false;
  v_failed  integer;
  v_window  timestamptz;
  v_locked  timestamptz;
  v_token   text;
  v_expires timestamptz;
BEGIN
  IF p_role IS NULL OR p_role NOT IN ('staff', 'admin') THEN
    RETURN pg_catalog.jsonb_build_object('ok', false, 'error', 'invalid_role');
  END IF;

  -- staff / admin とも: パスワードは数字4桁固定、15分の窓で5回失敗 → 30分ロック(ロックは role 別)
  v_max     := 5;
  v_lock    := interval '30 minutes';
  v_pattern := '^[0-9]{4}$';

  INSERT INTO public.shortstay_auth_attempts (scope) VALUES (p_role)
  ON CONFLICT (scope) DO NOTHING;

  SELECT * INTO v_att
  FROM public.shortstay_auth_attempts WHERE scope = p_role FOR UPDATE;

  IF v_att.locked_until IS NOT NULL AND v_att.locked_until > v_now THEN
    RETURN pg_catalog.jsonb_build_object('ok', false, 'error', 'locked',
                                         'locked_until', v_att.locked_until);
  END IF;

  IF p_pin IS NOT NULL AND p_pin ~ v_pattern THEN
    SELECT true INTO v_ok
    FROM public.shortstay_auth a
    WHERE a.role = p_role
      AND a.pin_hash = extensions.crypt(p_pin, a.pin_hash);
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
    IF v_failed >= v_max THEN
      v_locked := v_now + v_lock;
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

  DELETE FROM public.shortstay_sessions WHERE expires_at <= v_now;

  v_token   := pg_catalog.encode(extensions.gen_random_bytes(32), 'hex');
  v_expires := v_now + c_session;
  INSERT INTO public.shortstay_sessions (token_hash, role, expires_at)
  VALUES (public.ss_hash_token(v_token), p_role, v_expires);

  RETURN pg_catalog.jsonb_build_object('ok', true, 'token', v_token,
                                       'role', p_role, 'expires_at', v_expires);
END;
$$;

REVOKE ALL ON FUNCTION public.ss_login(text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ss_login(text, text) TO anon;

-- 自己検証(不一致なら例外 → 全体ロールバック)
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
      ('public.ss_hash_token(text)',              false, false),
      ('public.ss_require_session(text,text)',    false, true),
      ('public.ss_set_pin(text,text)',            false, true),
      ('public.ss_reset_attempts(text)',          false, true),
      ('public.ss_login(text,text)',              true,  true),
      ('public.ss_logout(text)',                  true,  true),
      ('public.ss_list_entries(text)',            true,  true),
      ('public.ss_upsert_entry(text,jsonb)',      true,  true),
      ('public.ss_delete_entry(text,uuid)',       true,  true),
      ('public.ss_delete_all_entries(text,text)', true,  true)
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

  SELECT count(*) INTO v_count FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'ss\_%';
  IF v_count <> 10 THEN RAISE EXCEPTION 'expected 10 ss_* functions in public, found %', v_count; END IF;

  -- 新仕様が実際に反映されていること(staff/admin とも4桁固定・5回/30分ロック)
  SELECT prosrc INTO v_src FROM pg_proc WHERE oid = 'public.ss_login(text,text)'::regprocedure;
  IF position('v_max     := 5;' in v_src) = 0
     OR position('v_max     := 10;' in v_src) <> 0
     OR position('{8,32}' in v_src) <> 0
     OR position('{6,32}' in v_src) <> 0
     OR (length(v_src) - length(replace(v_src, 'interval ''30 minutes''', ''))) / length('interval ''30 minutes''') <> 1
     OR position('^[0-9]{4}$' in v_src) = 0 THEN
    RAISE EXCEPTION 'password policy not reflected in ss_login';
  END IF;
  SELECT prosrc INTO v_src FROM pg_proc WHERE oid = 'public.ss_set_pin(text,text)'::regprocedure;
  IF position('^[0-9]{4}$' in v_src) = 0 OR position('{8,32}' in v_src) <> 0 OR position('{6,32}' in v_src) <> 0 THEN
    RAISE EXCEPTION 'password policy not reflected in ss_set_pin';
  END IF;
END $$;

COMMIT;

-- ロールバック(admin を8桁以上に戻す場合):
--   工程3の ss_set_pin / ss_login(admin 8〜32桁)に相当する定義を CREATE OR REPLACE で再実行する。
