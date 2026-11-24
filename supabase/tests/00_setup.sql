-- Enable pgTAP in the extensions schema (Supabase recommendation).
begin;
create extension if not exists pgtap with schema extensions;
commit;
