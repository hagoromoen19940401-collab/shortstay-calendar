-- 工程1: ショートステイ職員認証の基盤(追加のみ)
--
-- 対象: 認証テーブル3つ + 認証用関数6つ
-- 対象外: public.shortstay_entries、既存の allow_all policy、既存の GRANT は一切変更しない。
--         本番の既存データには触れない。service_role は使用しない。
--
-- 前提(本番で確認済み):
--   * public スキーマの DEFAULT PRIVILEGES により、新規テーブル・新規関数に
--     anon / authenticated の権限が自動付与される。
--   * pgcrypto は extensions スキーマに存在する。
--
-- 全体を1トランザクションで実行する。CREATE から REVOKE までの間に他セッションから
-- 見える状態は存在しない。末尾の検証でどれか1つでも不一致なら、全体がロールバックされる。
--
-- search_path は全関数で `pg_catalog, pg_temp` に固定する。
-- 関数内のオブジェクトはすべて public. / extensions. / pg_catalog. で完全修飾しているため、
-- public も extensions も search_path に含めない。

BEGIN;

-- ---------------------------------------------------------------------------
-- 0. 前提チェック(満たさなければ中止)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF to_regprocedure('extensions.crypt(text,text)') IS NULL
     OR to_regprocedure('extensions.gen_salt(text,integer)') IS NULL
     OR to_regprocedure('extensions.digest(text,text)') IS NULL
     OR to_regprocedure('extensions.gen_random_bytes(integer)') IS NULL THEN
    RAISE EXCEPTION 'pgcrypto functions not found in schema "extensions"';
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 1. テーブル(CREATE 直後に RLS 有効化 + 権限 REVOKE。policy は作らない)
-- ---------------------------------------------------------------------------

-- 1-1. PIN(ハッシュのみ。平文は保存しない)。role ごとに1行。
CREATE TABLE public.shortstay_auth (
  role       text PRIMARY KEY CHECK (role IN ('staff', 'admin')),
  pin_hash   text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.shortstay_auth ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.shortstay_auth FROM PUBLIC, anon, authenticated;

-- 1-2. セッション(トークンは SHA-256 ハッシュのみ保存)
CREATE TABLE public.shortstay_sessions (
  token_hash text PRIMARY KEY,
  role       text NOT NULL CHECK (role IN ('staff', 'admin')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE INDEX shortstay_sessions_expires_at_idx ON public.shortstay_sessions (expires_at);
ALTER TABLE public.shortstay_sessions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.shortstay_sessions FROM PUBLIC, anon, authenticated;

-- 1-3. ログイン失敗回数の制限。role ごとに1行(IP は使わない)。
--      staff 側を攻撃されても admin のログインは止まらない。
CREATE TABLE public.shortstay_auth_attempts (
  scope             text PRIMARY KEY CHECK (scope IN ('staff', 'admin')),
  failed_count      integer NOT NULL DEFAULT 0,
  window_started_at timestamptz NOT NULL DEFAULT now(),
  locked_until      timestamptz
);
ALTER TABLE public.shortstay_auth_attempts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.shortstay_auth_attempts FROM PUBLIC, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 2. 内部関数(anon / authenticated / PUBLIC から実行不可)
-- ---------------------------------------------------------------------------

-- 2-1. トークンのハッシュ化(SHA-256, hex)
CREATE FUNCTION public.ss_hash_token(p_token text)
RETURNS text
LANGUAGE sql
IMMUTABLE STRICT
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT pg_catalog.encode(extensions.digest(p_token, 'sha256'), 'hex');
$$;
REVOKE ALL ON FUNCTION public.ss_hash_token(text) FROM PUBLIC, anon, authenticated;

-- 2-2. セッション検証。有効なら role を返す。無効・期限切れ・権限不足は例外。
--      後続工程のデータ用 RPC(SECURITY DEFINER)から呼ぶ。
CREATE FUNCTION public.ss_require_session(p_token text, p_min_role text DEFAULT 'staff')
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_role text;
BEGIN
  IF p_min_role IS NULL OR p_min_role NOT IN ('staff', 'admin') THEN
    RAISE EXCEPTION 'invalid min role' USING ERRCODE = '22023';
  END IF;

  IF p_token IS NULL OR p_token = '' THEN
    RAISE EXCEPTION 'unauthorized' USING ERRCODE = '28000';
  END IF;

  SELECT s.role INTO v_role
  FROM public.shortstay_sessions s
  WHERE s.token_hash = public.ss_hash_token(p_token)
    AND s.expires_at > pg_catalog.now();

  IF v_role IS NULL THEN
    RAISE EXCEPTION 'unauthorized' USING ERRCODE = '28000';
  END IF;

  IF p_min_role = 'admin' AND v_role <> 'admin' THEN
    RAISE EXCEPTION 'forbidden' USING ERRCODE = '42501';
  END IF;

  RETURN v_role;
END;
$$;
REVOKE ALL ON FUNCTION public.ss_require_session(text, text) FROM PUBLIC, anon, authenticated;

-- 2-3. PIN 登録/変更。管理者が SQL Editor(postgres)から手動実行する想定。
--      PIN は migration に書かない。6桁以上の数字(最大32桁。管理者は8桁以上を推奨)。
--      staff と admin に同じ PIN は設定できない。
--      変更時はその role の既存セッションを失効させ、失敗カウンタ/ロックも解除する。
CREATE FUNCTION public.ss_set_pin(p_role text, p_pin text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF p_role IS NULL OR p_role NOT IN ('staff', 'admin') THEN
    RAISE EXCEPTION 'invalid role' USING ERRCODE = '22023';
  END IF;

  IF p_pin IS NULL OR p_pin !~ '^[0-9]{6,32}$' THEN
    RAISE EXCEPTION 'PIN must be 6 to 32 digits' USING ERRCODE = '22023';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.shortstay_auth a
    WHERE a.role <> p_role
      AND a.pin_hash = extensions.crypt(p_pin, a.pin_hash)
  ) THEN
    RAISE EXCEPTION 'PIN must differ between roles' USING ERRCODE = '22023';
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
REVOKE ALL ON FUNCTION public.ss_set_pin(text, text) FROM PUBLIC, anon, authenticated;

-- 2-4. ロック解除(失敗カウンタのリセット)。SQL Editor(postgres)から手動実行する想定。
--      攻撃でロックされた role を、PIN を変えずに復旧させる。
CREATE FUNCTION public.ss_reset_attempts(p_role text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF p_role IS NULL OR p_role NOT IN ('staff', 'admin') THEN
    RAISE EXCEPTION 'invalid role' USING ERRCODE = '22023';
  END IF;
  UPDATE public.shortstay_auth_attempts
  SET failed_count = 0, window_started_at = pg_catalog.now(), locked_until = NULL
  WHERE scope = p_role;
END;
$$;
REVOKE ALL ON FUNCTION public.ss_reset_attempts(text) FROM PUBLIC, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 3. ブラウザ(anon)から呼ぶ RPC。明示 GRANT するのはこの2つだけ。
-- ---------------------------------------------------------------------------

-- 3-1. ログイン。ログイン画面で role(staff / admin)を選ばせて渡す。
--      失敗は例外にせず jsonb で返す(例外にすると失敗回数の更新がロールバックされるため)。
--      成功: {"ok":true,"token":...,"role":...,"expires_at":...}
--      失敗: {"ok":false,"error":"invalid_pin"}
--            {"ok":false,"error":"locked","locked_until":...}
--            {"ok":false,"error":"invalid_role"}   (DB は書き換えない)
--      制限は role ごと(IP は使わない):
--        staff: 15分の窓で10回失敗 → 15分ロック
--        admin: 15分の窓で 5回失敗 → 30分ロック
--      ロックは新規ログインだけに効く。発行済みセッション(12時間)は影響を受けない。
CREATE FUNCTION public.ss_login(p_role text, p_pin text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  c_window  constant interval := interval '15 minutes';
  c_session constant interval := interval '12 hours';
  v_max     integer;
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
    v_max  := 5;
    v_lock := interval '30 minutes';
  ELSE
    v_max  := 10;
    v_lock := interval '15 minutes';
  END IF;

  INSERT INTO public.shortstay_auth_attempts (scope) VALUES (p_role)
  ON CONFLICT (scope) DO NOTHING;

  SELECT * INTO v_att
  FROM public.shortstay_auth_attempts WHERE scope = p_role FOR UPDATE;

  IF v_att.locked_until IS NOT NULL AND v_att.locked_until > v_now THEN
    RETURN pg_catalog.jsonb_build_object('ok', false, 'error', 'locked',
                                         'locked_until', v_att.locked_until);
  END IF;

  IF p_pin IS NOT NULL AND p_pin ~ '^[0-9]{6,32}$' THEN
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

-- 3-2. ログアウト(セッション削除)。トークンを知っている者だけが自分のセッションを消せる。
CREATE FUNCTION public.ss_logout(p_token text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_deleted integer;
BEGIN
  IF p_token IS NULL OR p_token = '' THEN
    RETURN false;
  END IF;
  DELETE FROM public.shortstay_sessions WHERE token_hash = public.ss_hash_token(p_token);
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted > 0;
END;
$$;
REVOKE ALL ON FUNCTION public.ss_logout(text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ss_logout(text) TO anon;

-- ---------------------------------------------------------------------------
-- 4. 自己検証(不一致なら例外 → 全体ロールバック)
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  r       record;
  v_oid   oid;
  v_proc  pg_proc%ROWTYPE;
  v_count integer;
BEGIN
  -- 4-1. テーブル: RLS ON / policy なし / PUBLIC・anon・authenticated の権限なし
  FOR r IN
    SELECT t AS name, ('public.' || t)::regclass AS reg
    FROM unnest(ARRAY['shortstay_auth', 'shortstay_sessions', 'shortstay_auth_attempts']) AS t
  LOOP
    IF NOT (SELECT c.relrowsecurity FROM pg_class c WHERE c.oid = r.reg) THEN
      RAISE EXCEPTION 'RLS is not enabled on %', r.name;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = r.name) THEN
      RAISE EXCEPTION 'unexpected policy on %', r.name;
    END IF;
    IF has_table_privilege('anon', r.reg, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       OR has_table_privilege('authenticated', r.reg, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
      RAISE EXCEPTION 'anon/authenticated still has privileges on %', r.name;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class c, aclexplode(c.relacl) x WHERE c.oid = r.reg AND x.grantee = 0) THEN
      RAISE EXCEPTION 'PUBLIC still has privileges on %', r.name;
    END IF;
  END LOOP;

  -- 4-2. 関数: 正確なシグネチャごとに SECURITY DEFINER / search_path / EXECUTE を確認
  FOR r IN
    SELECT * FROM (VALUES
      ('public.ss_hash_token(text)',          false, false),
      ('public.ss_require_session(text,text)', false, true),
      ('public.ss_set_pin(text,text)',         false, true),
      ('public.ss_reset_attempts(text)',       false, true),
      ('public.ss_login(text,text)',           true,  true),
      ('public.ss_logout(text)',               true,  true)
    ) AS v(sig, anon_exec, secdef)
  LOOP
    v_oid := to_regprocedure(r.sig);
    IF v_oid IS NULL THEN
      RAISE EXCEPTION 'function % not found', r.sig;
    END IF;
    SELECT * INTO v_proc FROM pg_proc WHERE oid = v_oid;

    IF v_proc.prosecdef <> r.secdef THEN
      RAISE EXCEPTION 'unexpected SECURITY DEFINER state on %', r.sig;
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM unnest(v_proc.proconfig) c
      WHERE replace(c, ' ', '') = 'search_path=pg_catalog,pg_temp'
    ) THEN
      RAISE EXCEPTION 'search_path is not pinned to pg_catalog, pg_temp on %', r.sig;
    END IF;
    IF has_function_privilege('anon', v_oid, 'EXECUTE') <> r.anon_exec THEN
      RAISE EXCEPTION 'unexpected anon EXECUTE state on %', r.sig;
    END IF;
    IF has_function_privilege('authenticated', v_oid, 'EXECUTE') THEN
      RAISE EXCEPTION 'authenticated can execute %', r.sig;
    END IF;
    IF v_proc.proacl IS NULL
       OR EXISTS (SELECT 1 FROM aclexplode(v_proc.proacl) x WHERE x.grantee = 0 AND x.privilege_type = 'EXECUTE') THEN
      RAISE EXCEPTION 'PUBLIC can execute %', r.sig;
    END IF;
  END LOOP;

  -- 4-3. public 内の ss_* 関数が上記6つだけであること(想定外のオーバーロードを検出)
  SELECT count(*) INTO v_count
  FROM pg_proc p
  WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'ss\_%';
  IF v_count <> 6 THEN
    RAISE EXCEPTION 'expected 6 ss_* functions in public, found %', v_count;
  END IF;
END $$;

COMMIT;

-- ---------------------------------------------------------------------------
-- ロールバック(この工程の取り消し。shortstay_entries には影響しない)
--   BEGIN;
--   DROP FUNCTION public.ss_logout(text);
--   DROP FUNCTION public.ss_login(text, text);
--   DROP FUNCTION public.ss_reset_attempts(text);
--   DROP FUNCTION public.ss_set_pin(text, text);
--   DROP FUNCTION public.ss_require_session(text, text);
--   DROP FUNCTION public.ss_hash_token(text);
--   DROP TABLE public.shortstay_auth_attempts;
--   DROP TABLE public.shortstay_sessions;
--   DROP TABLE public.shortstay_auth;
--   COMMIT;
-- ---------------------------------------------------------------------------
