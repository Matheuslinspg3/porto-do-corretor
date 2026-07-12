-- Fix leads RLS policy deduplication, maintenance policy restrictiveness,
-- and profile lookup mismatch for lead broker validation.

-- A) Drop legacy permissive policies that were coexisting with the v2 policies.
DROP POLICY IF EXISTS "Users can create leads" ON public.leads;
DROP POLICY IF EXISTS "Users can view leads based on role" ON public.leads;
DROP POLICY IF EXISTS "Users can update leads based on role" ON public.leads;

-- B) Recreate maintenance policies as RESTRICTIVE so they are ANDed with
-- the normal permissive business policies instead of acting as an OR bypass.
DROP POLICY IF EXISTS "Block inserts during maintenance" ON public.leads;
DROP POLICY IF EXISTS "Block updates during maintenance" ON public.leads;
DROP POLICY IF EXISTS "Block deletes during maintenance" ON public.leads;

CREATE POLICY "Block inserts during maintenance" ON public.leads
  AS RESTRICTIVE
  FOR INSERT
  TO authenticated
  WITH CHECK (NOT public.is_maintenance_blocked());

CREATE POLICY "Block updates during maintenance" ON public.leads
  AS RESTRICTIVE
  FOR UPDATE
  TO authenticated
  USING (NOT public.is_maintenance_blocked())
  WITH CHECK (NOT public.is_maintenance_blocked());

CREATE POLICY "Block deletes during maintenance" ON public.leads
  AS RESTRICTIVE
  FOR DELETE
  TO authenticated
  USING (NOT public.is_maintenance_blocked());

-- C) Correct lead responsible eligibility to compare auth user ids with profiles.user_id,
-- not profiles.id, which is the internal profile row id.
CREATE OR REPLACE FUNCTION public.is_lead_eligible_responsible(_uid uuid, _org uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.profiles p
    JOIN public.user_roles ur ON ur.user_id = p.user_id
    WHERE p.user_id = _uid
      AND p.organization_id = _org
      AND ur.role::text IN ('corretor', 'admin', 'sub_admin', 'leader', 'developer')
  );
$$;

REVOKE ALL ON FUNCTION public.is_lead_eligible_responsible(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.is_lead_eligible_responsible(uuid, uuid) TO authenticated;

-- D) Correct broker profile lookup to use profiles.user_id because leads.broker_id
-- stores auth.users.id / auth.uid(). Preserve the existing authorship and broker rules.
CREATE OR REPLACE FUNCTION public.protect_lead_authorship_and_broker()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_broker_org uuid;
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.created_by := COALESCE(auth.uid(), NEW.created_by);
  ELSIF TG_OP = 'UPDATE' THEN
    NEW.created_by := OLD.created_by;

    IF NEW.broker_id IS DISTINCT FROM OLD.broker_id
       AND auth.uid() IS NOT NULL
       AND NOT public.is_leads_org_manager(auth.uid()) THEN
      RAISE EXCEPTION 'Only organization managers can change lead responsible'
        USING ERRCODE = '42501';
    END IF;
  END IF;

  IF NEW.broker_id IS NOT NULL THEN
    SELECT organization_id INTO v_broker_org
    FROM public.profiles
    WHERE user_id = NEW.broker_id;

    IF v_broker_org IS NULL OR v_broker_org <> NEW.organization_id THEN
      RAISE EXCEPTION 'Broker does not belong to the lead organization'
        USING ERRCODE = 'check_violation';
    END IF;

    IF NOT public.is_lead_eligible_responsible(NEW.broker_id, NEW.organization_id) THEN
      RAISE EXCEPTION 'Broker role is not eligible to be assigned as lead responsible'
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

-- E) Final non-destructive verification. Fail the migration if maintenance policies
-- are not restrictive or if the legacy permissive policies still exist.
DO $$
DECLARE
  r record;
  legacy_count int;
BEGIN
  FOR r IN
    SELECT policyname, permissive
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'leads'
      AND policyname LIKE 'Block %'
  LOOP
    IF r.permissive <> 'RESTRICTIVE' THEN
      RAISE EXCEPTION 'Maintenance policy % is still %', r.policyname, r.permissive;
    END IF;
  END LOOP;

  SELECT count(*) INTO legacy_count
  FROM pg_policies
  WHERE schemaname = 'public'
    AND tablename = 'leads'
    AND policyname IN (
      'Users can create leads',
      'Users can view leads based on role',
      'Users can update leads based on role'
    );

  IF legacy_count > 0 THEN
    RAISE EXCEPTION 'Legacy leads policies still present: %', legacy_count;
  END IF;
END;
$$;
