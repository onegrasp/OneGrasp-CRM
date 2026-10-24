-- Harden manage_webhook_key.
--
-- Previously this SECURITY DEFINER function was granted to anon/authenticated
-- and took a p_user_id argument, so anyone who could reach the public API could
-- generate, read or revoke ANY user's webhook key (IDOR). The key-management
-- server functions now run with the service role and pass the *authenticated*
-- user's id, so anon/authenticated no longer need to execute it directly.
REVOKE EXECUTE ON FUNCTION public.manage_webhook_key(uuid, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.manage_webhook_key(uuid, text) FROM anon;
REVOKE EXECUTE ON FUNCTION public.manage_webhook_key(uuid, text) FROM authenticated;
GRANT  EXECUTE ON FUNCTION public.manage_webhook_key(uuid, text) TO service_role;

-- verify_webhook_key and insert_webhook_lead intentionally remain callable by
-- anon: the public lead webhook authenticates callers with the API key itself
-- (not a Supabase JWT), then looks up the owner and inserts the lead.
