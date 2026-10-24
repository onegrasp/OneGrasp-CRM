// Server-side auth guard for server functions.
//
// WHY: TanStack server functions are plain HTTP endpoints. Without an explicit
// check anyone on the internet can call them, so every sensitive function must
// verify the caller. The browser keeps its Supabase session in localStorage
// (see integrations/supabase/client.ts), so the session token can't be read
// from a cookie here — callers pass session.access_token in the request and we
// validate it against Supabase.
import { createClient } from "@supabase/supabase-js";

function anonClient(token: string) {
  const url = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL;
  const key = process.env.SUPABASE_PUBLISHABLE_KEY || process.env.VITE_SUPABASE_PUBLISHABLE_KEY;
  if (!url || !key) throw new Error("Supabase environment variables are not configured");
  return createClient(url, key, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

export type AuthedUser = { id: string; email: string | null; role: string };

// Resolves to the authenticated user, or throws if the token is missing/invalid.
export async function requireUser(token: unknown): Promise<AuthedUser> {
  if (typeof token !== "string" || !token) {
    throw new Error("Unauthorized: please sign in and try again.");
  }
  const { data, error } = await anonClient(token).auth.getUser(token);
  if (error || !data?.user) {
    throw new Error("Unauthorized: your session is invalid or has expired.");
  }
  const u = data.user;
  const role =
    (u.user_metadata?.role as string | undefined) ||
    (u.app_metadata?.role as string | undefined) ||
    "employee";
  return { id: u.id, email: u.email ?? null, role };
}

// Like requireUser, but also requires the admin role.
export async function requireAdmin(token: unknown): Promise<AuthedUser> {
  const user = await requireUser(token);
  if (user.role !== "admin") {
    throw new Error("Forbidden: this action requires an admin account.");
  }
  return user;
}
