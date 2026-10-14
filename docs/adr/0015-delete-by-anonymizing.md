# 0015 — Delete a person by anonymizing the record by default

## Status

Accepted (Keystone-MCP 0.6.0)

## Context

Operators need a supported way to remove personal data when someone asks to be
forgotten. Blocking leaves the email and history in the users database. A hard
delete removes the row but breaks traceability in audit logs that already store
only salted subject hashes.

## Decision

We add an optional users-directory capability `delete` and a `users_delete`
tool with a two-step confirmation flow. Only a full administrator may call it;
service accounts are refused like other mutating admin tools.

The operator chooses the outcome with `KEYSTONE_MCP_USERS_DELETE_MODE`
(default `anonymize`): either replace the row with a blocked pseudonym record
(`deleted:<sub_…>`) or remove the row entirely. The adapter builds the
pseudonym with the same salt as RBAC audit (`hash_subject`). Sessions and API
keys are revoked after a successful delete; references in `created_by` and
`revoked_by` are rewritten to the pseudonym marker. No new database column is
introduced — deletion time lives in `note`.

## Consequences

- GDPR-style requests can be handled without raw SQL; audit pseudonyms stay
  stable before and after deletion when the salt is set.
- Roles that enumerate administration tools by name must include `users_delete`
  to remain full administrators.
- External HTTP directories do not gain delete until their contract is extended
  separately; the built-in directory declares `delete`.

## Alternatives considered

- **Hard delete only** — simpler storage, but audit rows become unlinkable once
  the email is gone unless every event already used the pseudonym.
- **Delegate delete to HR roles** — rejected; irreversible personal-data removal
  stays with full administrators only.

## Links

- [users.md](../users.md#deleting-a-person)
- [user-directory.md](../user-directory.md)
- [compatibility.md](../compatibility.md)
