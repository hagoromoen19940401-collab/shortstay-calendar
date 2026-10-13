-- 工程2: shortstay_entries 用のデータ RPC(追加のみ)
--
-- 対象: 新規関数4つ(一覧 / 1件追加・更新 / 1件削除 / 全件削除[admin のみ])
-- 対象外: public.shortstay_entries の定義・データ・RLS・policy(allow_all)・GRANT は一切変更しない。
--         既存の列構成(23列)とデータ形式をそのまま使う。
--
-- 認証は工程1の ss_require_session(token, min_role) で行う。
-- 全関数: SECURITY DEFINER / search_path = pg_catalog, pg_temp / 完全修飾。
-- 新規関数は作成直後に PUBLIC / anon / authenticated から EXECUTE を REVOKE し、
-- ブラウザから呼ぶ4つだけ anon に明示 GRANT する(認可は関数内のトークン検証で行う)。
--
-- 全体を1トランザクションで実行。末尾の自己検証が不一致なら全体ロールバック。

BEGIN;

DO $$
BEGIN
  IF to_regprocedure('public.ss_require_session(text,text)') IS NULL THEN
    RAISE EXCEPTION 'step1 (ss_require_session) is not installed';
  END IF;
  IF to_regclass('public.shortstay_entries') IS NULL THEN
    RAISE EXCEPTION 'public.shortstay_entries not found';
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 1. 一覧取得(staff 以上)。全23列を snake_case のまま jsonb 配列で返す。
-- ---------------------------------------------------------------------------
CREATE FUNCTION public.ss_list_entries(p_token text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_result jsonb;
BEGIN
  PERFORM public.ss_require_session(p_token, 'staff');

  SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(e) ORDER BY e.start_date, e.id),
                  '[]'::pg_catalog.jsonb)
  INTO v_result
  FROM public.shortstay_entries e;

  RETURN v_result;
END;
$$;
REVOKE ALL ON FUNCTION public.ss_list_entries(text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ss_list_entries(text) TO anon;

-- ---------------------------------------------------------------------------
-- 2. 1件追加・更新(staff 以上)
--    p_entry は現行アプリが送っている列名(snake_case)の jsonb。
--    id が無ければ採番。updated_at はサーバー側で設定する。
--    競合防止: p_entry.expected_updated_at(読込時の updated_at)が付いていて、
--    DB の値と違えば更新せず {"ok":false,"error":"conflict","current":{...}} を返す。
--    expected 付きで行が既に無ければ {"ok":false,"error":"deleted"}。
--    成功: {"ok":true,"entry":{...全列...}}
--    start_undecided / end_undecided 列は現行アプリが書かないので触らない。
-- ---------------------------------------------------------------------------
CREATE FUNCTION public.ss_upsert_entry(p_token text, p_entry jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  c_max_text constant integer := 2000;
  c_max_list constant integer := 100;
  v_key      text;
  v_id       uuid;
  v_name     text;
  v_exp      timestamptz;
  v_existing public.shortstay_entries%ROWTYPE;
  v_has      boolean;
  v_ci       pg_catalog.jsonb;
  v_co       pg_catalog.jsonb;
  v_row      public.shortstay_entries%ROWTYPE;
BEGIN
  PERFORM public.ss_require_session(p_token, 'staff');

  IF p_entry IS NULL OR pg_catalog.jsonb_typeof(p_entry) <> 'object' THEN
    RAISE EXCEPTION 'entry must be a json object' USING ERRCODE = '22023';
  END IF;

  v_name := pg_catalog.btrim(COALESCE(p_entry->>'name', ''));
  IF v_name = '' THEN
    RAISE EXCEPTION 'name is required' USING ERRCODE = '22023';
  END IF;

  FOREACH v_key IN ARRAY ARRAY[
    'name', 'start_date', 'start_hour', 'end_date', 'end_hour', 'room',
    'transport_method', 'transport_checkin', 'transport_checkout', 'meal_info',
    'last_bowel_date', 'bowel_amount', 'last_bath_date', 'bath_count',
    'stay_note', 'writer', 'note', 'id', 'expected_updated_at'
  ] LOOP
    IF pg_catalog.char_length(p_entry->>v_key) > c_max_text THEN
      RAISE EXCEPTION 'field % is too long', v_key USING ERRCODE = '22001';
    END IF;
  END LOOP;

  v_ci := CASE WHEN pg_catalog.jsonb_typeof(p_entry->'checklist_checkin') = 'array'
               THEN p_entry->'checklist_checkin' ELSE '[]'::pg_catalog.jsonb END;
  v_co := CASE WHEN pg_catalog.jsonb_typeof(p_entry->'checklist_checkout') = 'array'
               THEN p_entry->'checklist_checkout' ELSE '[]'::pg_catalog.jsonb END;
  IF pg_catalog.jsonb_typeof(p_entry->'checklist_checkin') NOT IN ('array', 'null')
     OR pg_catalog.jsonb_typeof(p_entry->'checklist_checkout') NOT IN ('array', 'null') THEN
    RAISE EXCEPTION 'checklist must be an array' USING ERRCODE = '22023';
  END IF;
  IF pg_catalog.jsonb_array_length(v_ci) > c_max_list
     OR pg_catalog.jsonb_array_length(v_co) > c_max_list
     OR pg_catalog.length(v_ci::text) > 20000
     OR pg_catalog.length(v_co::text) > 20000 THEN
    RAISE EXCEPTION 'checklist is too large' USING ERRCODE = '22001';
  END IF;

  IF NULLIF(p_entry->>'id', '') IS NULL THEN
    v_id := pg_catalog.gen_random_uuid();
  ELSE
    v_id := (p_entry->>'id')::uuid;
  END IF;

  v_exp := NULLIF(p_entry->>'expected_updated_at', '')::timestamptz;

  SELECT * INTO v_existing
  FROM public.shortstay_entries WHERE id = v_id FOR UPDATE;
  v_has := FOUND;

  IF v_exp IS NOT NULL THEN
    IF NOT v_has THEN
      RETURN pg_catalog.jsonb_build_object('ok', false, 'error', 'deleted');
    END IF;
    IF v_existing.updated_at IS DISTINCT FROM v_exp THEN
      RETURN pg_catalog.jsonb_build_object('ok', false, 'error', 'conflict',
                                           'current', pg_catalog.to_jsonb(v_existing));
    END IF;
  END IF;

  INSERT INTO public.shortstay_entries AS e (
    id, name, start_date, start_hour, end_date, end_hour, room,
    transport_method, transport_checkin, transport_checkout, meal_info,
    last_bowel_date, bowel_amount, last_bath_date, bath_count,
    stay_note, writer, note, checklist_checkin, checklist_checkout, updated_at
  ) VALUES (
    v_id, v_name,
    NULLIF(pg_catalog.btrim(p_entry->>'start_date'), '')::date,
    NULLIF(p_entry->>'start_hour', ''),
    NULLIF(pg_catalog.btrim(p_entry->>'end_date'), '')::date,
    NULLIF(p_entry->>'end_hour', ''),
    COALESCE(p_entry->>'room', ''),
    COALESCE(p_entry->>'transport_method', ''),
    COALESCE(p_entry->>'transport_checkin', ''),
    COALESCE(p_entry->>'transport_checkout', ''),
    COALESCE(p_entry->>'meal_info', ''),
    NULLIF(pg_catalog.btrim(p_entry->>'last_bowel_date'), '')::date,
    COALESCE(p_entry->>'bowel_amount', ''),
    NULLIF(pg_catalog.btrim(p_entry->>'last_bath_date'), '')::date,
    COALESCE(p_entry->>'bath_count', ''),
    COALESCE(p_entry->>'stay_note', ''),
    COALESCE(p_entry->>'writer', ''),
    COALESCE(p_entry->>'note', ''),
    v_ci, v_co, pg_catalog.now()
  )
  ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    start_date = EXCLUDED.start_date,
    start_hour = EXCLUDED.start_hour,
    end_date = EXCLUDED.end_date,
    end_hour = EXCLUDED.end_hour,
    room = EXCLUDED.room,
    transport_method = EXCLUDED.transport_method,
    transport_checkin = EXCLUDED.transport_checkin,
    transport_checkout = EXCLUDED.transport_checkout,
    meal_info = EXCLUDED.meal_info,
    last_bowel_date = EXCLUDED.last_bowel_date,
    bowel_amount = EXCLUDED.bowel_amount,
    last_bath_date = EXCLUDED.last_bath_date,
    bath_count = EXCLUDED.bath_count,
    stay_note = EXCLUDED.stay_note,
    writer = EXCLUDED.writer,
    note = EXCLUDED.note,
    checklist_checkin = EXCLUDED.checklist_checkin,
    checklist_checkout = EXCLUDED.checklist_checkout,
    updated_at = EXCLUDED.updated_at
  RETURNING e.* INTO v_row;

  RETURN pg_catalog.jsonb_build_object('ok', true, 'entry', pg_catalog.to_jsonb(v_row));
END;
$$;
REVOKE ALL ON FUNCTION public.ss_upsert_entry(text, jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ss_upsert_entry(text, jsonb) TO anon;

-- ---------------------------------------------------------------------------
-- 3. 1件削除(staff 以上)。削除したら true、該当なしなら false。
-- ---------------------------------------------------------------------------
CREATE FUNCTION public.ss_delete_entry(p_token text, p_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_deleted integer;
BEGIN
  PERFORM public.ss_require_session(p_token, 'staff');

  IF p_id IS NULL THEN
    RAISE EXCEPTION 'id is required' USING ERRCODE = '22023';
  END IF;

  DELETE FROM public.shortstay_entries WHERE id = p_id;
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted > 0;
END;
$$;
REVOKE ALL ON FUNCTION public.ss_delete_entry(text, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ss_delete_entry(text, uuid) TO anon;

-- ---------------------------------------------------------------------------
-- 4. 全件削除(admin のみ)。確認文字列が一致しなければ実行しない。削除件数を返す。
--    staff のトークンでは 'forbidden'(42501)。
--    (WHERE true: 全行削除を明示。WHERE 無し DELETE を拒否する設定への対策)
-- ---------------------------------------------------------------------------
CREATE FUNCTION public.ss_delete_all_entries(p_token text, p_confirm text)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_deleted integer;
BEGIN
  PERFORM public.ss_require_session(p_token, 'admin');

  IF p_confirm IS DISTINCT FROM 'DELETE_ALL_SHORTSTAY_ENTRIES' THEN
    RAISE EXCEPTION 'confirmation text mismatch' USING ERRCODE = '22023';
  END IF;

  DELETE FROM public.shortstay_entries WHERE true;
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END;
$$;
REVOKE ALL ON FUNCTION public.ss_delete_all_entries(text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ss_delete_all_entries(text, text) TO anon;

-- ---------------------------------------------------------------------------
-- 5. 自己検証(不一致なら例外 → 全体ロールバック)
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  r       record;
  v_oid   oid;
  v_proc  pg_proc%ROWTYPE;
  v_count integer;
BEGIN
  FOR r IN
    SELECT * FROM (VALUES
      ('public.ss_hash_token(text)',            false),
      ('public.ss_require_session(text,text)',  false),
      ('public.ss_set_pin(text,text)',          false),
      ('public.ss_reset_attempts(text)',        false),
      ('public.ss_login(text,text)',            true),
      ('public.ss_logout(text)',                true),
      ('public.ss_list_entries(text)',          true),
      ('public.ss_upsert_entry(text,jsonb)',    true),
      ('public.ss_delete_entry(text,uuid)',     true),
      ('public.ss_delete_all_entries(text,text)', true)
    ) AS v(sig, anon_exec)
  LOOP
    v_oid := to_regprocedure(r.sig);
    IF v_oid IS NULL THEN
      RAISE EXCEPTION 'function % not found', r.sig;
    END IF;
    SELECT * INTO v_proc FROM pg_proc WHERE oid = v_oid;

    IF r.sig <> 'public.ss_hash_token(text)' AND NOT v_proc.prosecdef THEN
      RAISE EXCEPTION 'SECURITY DEFINER missing on %', r.sig;
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM unnest(v_proc.proconfig) c
      WHERE replace(c, ' ', '') = 'search_path=pg_catalog,pg_temp'
    ) THEN
      RAISE EXCEPTION 'search_path is not pinned on %', r.sig;
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

  SELECT count(*) INTO v_count
  FROM pg_proc p
  WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'ss\_%';
  IF v_count <> 10 THEN
    RAISE EXCEPTION 'expected 10 ss_* functions in public, found %', v_count;
  END IF;
END $$;

COMMIT;

-- ---------------------------------------------------------------------------
-- ロールバック(この工程の取り消し。工程1と shortstay_entries には影響しない)
--   BEGIN;
--   DROP FUNCTION public.ss_delete_all_entries(text, text);
--   DROP FUNCTION public.ss_delete_entry(text, uuid);
--   DROP FUNCTION public.ss_upsert_entry(text, jsonb);
--   DROP FUNCTION public.ss_list_entries(text);
--   COMMIT;
-- ---------------------------------------------------------------------------
