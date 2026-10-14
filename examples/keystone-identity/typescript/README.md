# keystoneIdentity.ts

Reference verifier for `X-Keystone-Identity`, for services built on the
TypeScript MCP SDK (`@modelcontextprotocol/sdk`). Not an npm package --
copy `keystoneIdentity.ts` into your own service and `npm install jose`.

## Wiring it into a server on `@modelcontextprotocol/sdk`

Inside a tool handler, the incoming HTTP request's headers are on
`extra.requestInfo.headers` (the SDK's `RequestHandlerExtra`):

```ts
server.tool("myTool", schema, async (args, extra) => {
  const header = extra.requestInfo?.headers["x-keystone-identity"];
  const identity = await verifyKeystoneIdentity(
    Array.isArray(header) ? header[0] : header,
    {
      secrets: [process.env.MYSVC_IDENTITY_SECRET!],
      audience: "mysvc-mcp",
      issuer: process.env.KEYSTONE_MCP_BASE_URL!.replace(/\/$/, ""),
    },
  );
  // identity.sub, identity.roles, identity.subType, ...
});
```

`list_tools` calls never carry the header -- only verify it inside a tool
call.

## Manual check against the shared test vector

```bash
npm install
npx tsx keystoneIdentity.ts ../test-vector.json
```

Prints `ok` when the TypeScript verifier accepts the same token the Python
reference and its tests accept. Node.js is not part of this project's CI;
this check is manual only.
