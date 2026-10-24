import { createServerFn } from "@tanstack/react-start";
import { supabaseAdmin } from "@/integrations/supabase/client.server";
import { requireAdmin } from "./auth-guard";

// token: the caller's Supabase access token (session.access_token). Only an
// authenticated admin may create users — without this check the service-role
// client below would let anyone create accounts with any role.
type CreateUserInput = { email: string; password: string; role?: string; token: string };

function validateEmail(e: string) {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);
}

export const createUser = createServerFn({ method: "POST" })
  .inputValidator((d: CreateUserInput) => d)
  .handler(async ({ data }) => {
    // Authorize first: must be a signed-in admin.
    await requireAdmin(data.token);

    if (!data?.email || !data?.password) throw new Error("Email and password are required");
    if (!validateEmail(data.email)) throw new Error("Invalid email address");
    if (String(data.password).length < 8) throw new Error("Password must be at least 8 characters");

    const role = data.role ?? "employee";

    try {
      const { error } = await supabaseAdmin.auth.admin.createUser({
        email: data.email,
        password: data.password,
        email_confirm: true,
        user_metadata: { role, name: data.email },
      });
      if (error) throw new Error(error.message || "Failed to create user");
      return { ok: true };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to create user";
      console.error("createUser error:", message);
      throw new Error(message);
    }
  });
