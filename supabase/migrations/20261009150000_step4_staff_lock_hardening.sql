-- 工程4: staff の総当たり対策を強化(ss_login の置き換えのみ)
--
--   staff : 15分の窓で 5回失敗 → 30分ロック   (変更: 旧 10回 → 15分ロック)
--   admin : 15分の窓で 5回失敗 → 30分ロック   (変更なし)
--   ロックは role 別のまま。段階的な長時間ロックは導入しない。
--   PIN 仕様は変更しない: staff=数字4桁固定 / admin=数字8桁以上(最大32桁)
--
-- 対象: ss_login(text,text) の置き換え(CREATE OR REPLACE)。
-- 対象外: shortstay_entries、allow_all、既存GRANT、認証3テーブル、他の関数、セッション方式。
-- SECURITY DEFINER / search_path = pg_catalog, pg_temp / 完全修飾は維持。置き換え後に REVOKE→GRANT をやり直し、
-- 末尾で全10関数の権限を自己検証する。

BEGIN;

DO $$
BEGIN
  IF to_regprocedure('public.ss_login(text,text)') IS NULL THEN
    RAISE EXCEPTION 'ss_login is not installed';
  END IF;
END $$;

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

  IF p_role = 'admin' THEN
    v_max     := 5;
    v_lock    := interval '30 minutes';
    v_pattern := '^[0-9]{8,32}$';
  ELSE
    v_max     := 5;
    v_lock    := interval '30 minutes';
    v_pattern := '^[0-9]{4}$';
  END IF;

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

  -- ロック設定とPIN規則が実際に反映されていること
  SELECT prosrc INTO v_src FROM pg_proc WHERE oid = 'public.ss_login(text,text)'::regprocedure;
  IF (length(v_src) - length(replace(v_src, 'v_max     := 5;', ''))) / length('v_max     := 5;') <> 2
     OR position('v_max     := 10;' in v_src) <> 0
     OR (length(v_src) - length(replace(v_src, 'interval ''30 minutes''', ''))) / length('interval ''30 minutes''') <> 2
     OR (length(v_src) - length(replace(v_src, 'interval ''15 minutes''', ''))) / length('interval ''15 minutes''') <> 1
     OR position('^[0-9]{4}$' in v_src) = 0
     OR position('^[0-9]{8,32}$' in v_src) = 0 THEN
    RAISE EXCEPTION 'lock settings not reflected in ss_login';
  END IF;
  SELECT prosrc INTO v_src FROM pg_proc WHERE oid = 'public.ss_set_pin(text,text)'::regprocedure;
  IF position('^[0-9]{4}$' in v_src) = 0 OR position('^[0-9]{8,32}$' in v_src) = 0 THEN
    RAISE EXCEPTION 'PIN policy changed unexpectedly in ss_set_pin';
  END IF;
END $$;

COMMIT;

-- ロールバック(staff を 10回/15分ロックに戻す場合):
--   工程3の ss_login を CREATE OR REPLACE で再実行する。
