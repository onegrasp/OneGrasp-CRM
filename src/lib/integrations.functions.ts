import { createServerFn } from "@tanstack/react-start";
import { supabaseAdmin } from "@/integrations/supabase/client.server";
import { requireUser } from "./auth-guard";

// SECURITY: the webhook key is derived from the *authenticated* user, never a
// userId sent by the client. Previously these functions took a `userId` and
// passed it straight to a SECURITY DEFINER RPC callable with the anon key, so
// anyone could read, regenerate or revoke any user's webhook key (IDOR). Now
// the caller proves who they are with their session token and can only touch
// their own key.
type TokenInput = { token: string };

export const generateWebhookKey = createServerFn({ method: "POST" })
  .inputValidator((d: TokenInput) => d)
  .handler(async ({ data }) => {
    const user = await requireUser(data.token);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- RPC not in generated types
    const { data: key, error } = await (supabaseAdmin as any).rpc("manage_webhook_key", {
      p_user_id: user.id,
      p_action: "generate",
    });
    if (error) throw new Error(error.message);
    return { key: key as string };
  });

export const getWebhookKey = createServerFn({ method: "POST" })
  .inputValidator((d: TokenInput) => d)
  .handler(async ({ data }) => {
    const user = await requireUser(data.token);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- RPC not in generated types
    const { data: key } = await (supabaseAdmin as any).rpc("manage_webhook_key", {
      p_user_id: user.id,
      p_action: "get",
    });
    return { key: (key as string | null) ?? null };
  });

export const revokeWebhookKey = createServerFn({ method: "POST" })
  .inputValidator((d: TokenInput) => d)
  .handler(async ({ data }) => {
    const user = await requireUser(data.token);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- RPC not in generated types
    const { error } = await (supabaseAdmin as any).rpc("manage_webhook_key", {
      p_user_id: user.id,
      p_action: "revoke",
    });
    if (error) throw new Error(error.message);
    return { ok: true };
  });
