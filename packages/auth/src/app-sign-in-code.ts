import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthEndpoint, createAuthMiddleware } from "better-auth/api";

/** Stored hashed (see `verification.storeIdentifier`), so the table never holds a usable code. */
export const APP_SIGN_IN_CODE_PREFIX = "app-sign-in-";
const CODE_EXPIRES_MS = 60_000;

const invalidCode = () =>
  new APIError("BAD_REQUEST", { code: "INVALID_CODE", message: "Invalid code" });
const s256 = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");

/**
 * Must follow `expo()`: swaps the session cookie it puts in an app-scheme callback for a one-time
 * code that only the app holding the verifier for `challenge` can exchange, so another app that
 * claims the scheme cannot take the session.
 */
export function appSignInCode(): BetterAuthPlugin {
  return {
    id: "app-sign-in-code",
    hooks: {
      after: [
        {
          matcher: (context) => !!context.path?.startsWith("/callback"),
          handler: createAuthMiddleware(async (ctx) => {
            const location = ctx.context.responseHeaders?.get("location");
            if (!location || !URL.canParse(location)) return;
            const url = new URL(location);
            const challenge = url.searchParams.get("challenge");
            // Older app builds send no challenge and keep the cookie.
            if (url.protocol === "http:" || url.protocol === "https:" || !challenge) return;
            const token = url.searchParams
              .get("cookie")
              ?.match(/(?:^|,\s*)(?:__Secure-)?better-auth\.session_token=([^;,]*)/)?.[1];
            url.searchParams.delete("cookie");
            url.searchParams.delete("challenge");
            if (token) {
              const code = randomBytes(32).toString("base64url");
              await ctx.context.internalAdapter.createVerificationValue({
                identifier: `${APP_SIGN_IN_CODE_PREFIX}${code}`,
                value: JSON.stringify({ token: decodeURIComponent(token), challenge }),
                expiresAt: new Date(Date.now() + CODE_EXPIRES_MS),
              });
              url.searchParams.set("code", code);
            }
            ctx.setHeader("location", url.toString());
          }),
        },
      ],
    },
    endpoints: {
      appSignInToken: createAuthEndpoint("/app-sign-in/token", { method: "POST" }, async (ctx) => {
        const { code, verifier } = (ctx.body ?? {}) as { code?: unknown; verifier?: unknown };
        if (typeof code !== "string" || typeof verifier !== "string" || verifier.length < 43)
          throw invalidCode();
        // Consuming is atomic, so a code works once even when the verifier is wrong.
        const stored = await ctx.context.internalAdapter.consumeVerificationValue(
          `${APP_SIGN_IN_CODE_PREFIX}${code}`,
        );
        const grant =
          stored && stored.expiresAt.getTime() > Date.now()
            ? (JSON.parse(stored.value) as { token: string; challenge: string })
            : null;
        const expected = Buffer.from(grant?.challenge ?? "");
        const actual = Buffer.from(s256(verifier));
        if (!grant || expected.length !== actual.length || !timingSafeEqual(expected, actual))
          throw invalidCode();
        return ctx.json({ token: grant.token });
      }),
    },
  };
}
