// Reference verifier for Keystone-MCP's signed identity assertion.
//
// Standalone, no dependency on Keystone-MCP itself -- only `jose`. Copy this
// file (or vendor its logic) into your own upstream service; it is not
// published as an npm package. See
// ../../../docs/connecting-services.md (section "Who is calling:
// X-Keystone-Identity") for the full contract.
//
// Usage (HS256):
//   import { IdentityError, verifyKeystoneIdentity } from "./keystoneIdentity.js";
//   const identity = await verifyKeystoneIdentity(header, {
//     secrets: [process.env.MYSVC_IDENTITY_SECRET!],
//     audience: "mysvc-mcp",
//   });
//
// Usage (ES256, Keystone JWKS):
//   const identity = await verifyKeystoneIdentity(header, {
//     jwksUrl: "https://keystone.example/.well-known/keystone-identity-jwks.json",
//     audience: "mysvc-mcp",
//     algorithms: ["ES256"],
//   });

import { createRemoteJWKSet, jwtVerify } from "jose";

/** JWT header `typ` Keystone-MCP stamps on every assertion. */
const IDENTITY_TYP = "keystone-identity+jwt";

const HS256_ALGORITHMS = ["HS256"];
const ES256_ALGORITHMS = ["ES256"];

export class IdentityError extends Error {}

export interface KeystoneIdentity {
  sub: string;
  subType: string;
  email?: string;
  roles: string[];
  rbac: string;
  authMethod: string;
  interactive: boolean;
  clientId?: string;
  taskId: string;
  mcpMethod: string;
  mcpTarget: string;
  jti: string;
}

export interface VerifyKeystoneIdentityOptions {
  /** Tried in order for HS256 (secret rotation). */
  secrets?: string[];
  /** Keystone `/.well-known/keystone-identity-jwks.json` for ES256. */
  jwksUrl?: string;
  /** Required: this upstream's own registry entry `name` (not `namespace`). */
  audience: string;
  /** Checked only when given. */
  issuer?: string;
  leewaySeconds?: number;
  /** Pin allowed algorithms; never read from the token. */
  algorithms?: string[];
}

export async function verifyKeystoneIdentity(
  token: string | null | undefined,
  {
    secrets,
    jwksUrl,
    audience,
    issuer,
    leewaySeconds = 30,
    algorithms,
  }: VerifyKeystoneIdentityOptions,
): Promise<KeystoneIdentity> {
  if (!token) {
    throw new IdentityError("missing X-Keystone-Identity");
  }
  if (!audience) {
    throw new IdentityError("audience is required");
  }
  if (secrets?.length && jwksUrl) {
    throw new IdentityError("pass either secrets (HS256) or jwksUrl (ES256), not both");
  }
  if (!secrets?.length && !jwksUrl) {
    throw new IdentityError("secrets or jwksUrl is required");
  }

  if (jwksUrl) {
    const allowed = algorithms ?? ES256_ALGORITHMS;
    try {
      const { payload, protectedHeader } = await jwtVerify(token, createRemoteJWKSet(new URL(jwksUrl)), {
        algorithms: allowed,
        audience,
        issuer,
        clockTolerance: leewaySeconds,
        requiredClaims: ["exp", "iat", "aud", "sub"],
      });
      if (protectedHeader.typ !== IDENTITY_TYP) {
        throw new IdentityError(`unexpected typ: ${String(protectedHeader.typ)}`);
      }
      return claimsToIdentity(payload as Record<string, unknown>);
    } catch (err) {
      if (err instanceof IdentityError) {
        throw err;
      }
      throw new IdentityError(`signature or claims rejected: ${String(err)}`);
    }
  }

  const allowed = algorithms ?? HS256_ALGORITHMS;
  let lastError: unknown;
  for (const secret of secrets!) {
    try {
      const { payload, protectedHeader } = await jwtVerify(
        token,
        new TextEncoder().encode(secret),
        {
          algorithms: allowed,
          audience,
          issuer,
          clockTolerance: leewaySeconds,
          requiredClaims: ["exp", "iat", "aud", "sub"],
        },
      );
      if (protectedHeader.typ !== IDENTITY_TYP) {
        throw new IdentityError(`unexpected typ: ${String(protectedHeader.typ)}`);
      }
      return claimsToIdentity(payload as Record<string, unknown>);
    } catch (err) {
      if (err instanceof IdentityError) {
        throw err;
      }
      lastError = err;
    }
  }
  throw new IdentityError(`signature or claims rejected: ${String(lastError)}`);
}

function claimsToIdentity(payload: Record<string, unknown>): KeystoneIdentity {
  return {
    sub: payload.sub as string,
    subType: (payload.sub_type as string) ?? "human",
    email: payload.email as string | undefined,
    roles: (payload.roles as string[]) ?? [],
    rbac: (payload.rbac as string) ?? "off",
    authMethod: (payload.auth_method as string) ?? "unknown",
    interactive: Boolean(payload.interactive),
    clientId: payload.client_id as string | undefined,
    taskId: (payload.task_id as string) ?? "",
    mcpMethod: (payload.mcp_method as string) ?? "",
    mcpTarget: (payload.mcp_target as string) ?? "",
    jti: (payload.jti as string) ?? "",
  };
}

// Manual check against the shared test vector:
//   npx tsx keystoneIdentity.ts ../test-vector.json
// (see ../README.md). Not run in CI -- Node.js is not part of this
// project's toolchain; this is here purely so a human can confirm the two
// reference verifiers agree on the same token.
if (import.meta.url === `file://${process.argv[1]}`) {
  const fs = await import("node:fs/promises");
  const vectorPath = process.argv[2];
  if (!vectorPath) {
    console.error("usage: tsx keystoneIdentity.ts <test-vector.json>");
    process.exit(1);
  }
  const vector = JSON.parse(await fs.readFile(vectorPath, "utf-8"));
  try {
    // The shared vector is a fixed, long-expired token by the time anyone
    // runs this (see test-vector.json's _comment): verify it as of the
    // moment it was minted (`vector.now`), not the real wall clock, the
    // same carve-out the Python reference's own vector test makes.
    const { payload, protectedHeader } = await jwtVerify(
      vector.token,
      new TextEncoder().encode(vector.secret),
      {
        algorithms: HS256_ALGORITHMS,
        audience: vector.audience,
        issuer: vector.issuer,
        currentDate: new Date(vector.now * 1000),
      },
    );
    if (protectedHeader.typ !== IDENTITY_TYP) {
      throw new Error(`unexpected typ: ${String(protectedHeader.typ)}`);
    }
    for (const [key, value] of Object.entries(vector.claims)) {
      if (JSON.stringify(payload[key]) !== JSON.stringify(value)) {
        throw new Error(`claim ${key} mismatch: ${JSON.stringify(payload[key])} != ${JSON.stringify(value)}`);
      }
    }
    console.log("ok");
  } catch (err) {
    console.error("FAILED:", err);
    process.exit(1);
  }
}
