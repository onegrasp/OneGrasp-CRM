import { createServerFn } from "@tanstack/react-start";
import { supabaseAdmin } from "@/integrations/supabase/client.server";

// Optional one-time bootstrap of the first admin account.
//
// SECURITY: credentials are NEVER hard-coded. The admin email and password are
// read from server-side env vars (ADMIN_SETUP_EMAIL / ADMIN_SETUP_PASSWORD). If
// they are not set, this function does nothing, so it can be safely called from
// the login screen without exposing any credential. Remove the env vars once
// the admin exists.
export const ensureAdmin = createServerFn({ method: "POST" }).handler(async () => {
  const email = process.env.ADMIN_SETUP_EMAIL;
  const password = process.env.ADMIN_SETUP_PASSWORD;

  if (!email || !password) {
    // Not configured — nothing to do. No default credentials exist.
    return { ok: true, created: false, configured: false };
  }
  if (password.length < 12) {
    return { ok: false, error: "ADMIN_SETUP_PASSWORD must be at least 12 characters." };
  }

  const { data: list, error: listErr } = await supabaseAdmin.auth.admin.listUsers({
    page: 1,
    perPage: 200,
  });
  if (listErr) return { ok: false, error: listErr.message };

  const exists = list.users.some((u) => u.email?.toLowerCase() === email.toLowerCase());
  if (exists) return { ok: true, created: false, configured: true };

  const { error } = await supabaseAdmin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { name: "OneGrasp Admin", role: "admin" },
  });
  if (error) return { ok: false, error: error.message };
  return { ok: true, created: true, configured: true };
});
