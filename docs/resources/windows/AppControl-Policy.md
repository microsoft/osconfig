# Microsoft.Windows/AppControl/Policy

Specifies an [App Control for Business](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/appcontrol) policy on the device. This resource allows you to deploy, query, and remove application control policies.

Requires Windows **build 22621** or later.

## Properties

### `id`

The GUID that identifies the policy.

- `BF61FE40-8929-4FDF-9EC2-F7A767717F0B`

### `content`

The policy content to deploy. Can be either:

- A **base64-encoded** compiled binary policy (`.cip` file content)
- A **raw XML** policy string

Not returned by `get` or `list`.

### `baseId`

The base policy ID. For a base policy this equals `id`; for a supplemental policy it points to the parent.

### `friendlyName`

The display name of the policy as set in the policy metadata.

### `version`

The version of the policy.

### `isBasePolicy`

Whether this is a base policy (as opposed to a supplemental policy). Derived from `id == baseId`.

### `isDeployed`

Whether the policy file is currently present on disk.

### `isEffective`

Whether the policy is currently active and loaded by the kernel.

### `isEnforced`

Whether the policy is in enforcement mode (i.e. it does **not** have the `Enabled:Audit Mode` option).

### `isAuthorized`

Whether the policy is authorized. If the policy requires a token, this reflects the token authorization state; otherwise it matches `isEffective`.

### `isSigned`

Whether the policy has a valid signature.

### `isSystemPolicy`

Whether this is a Microsoft-provided system policy (e.g. the vulnerable driver blocklist).

### `options`

An array of policy option strings (e.g. `["Enabled:Audit Mode", "Enabled:UMCI"]`).

### `status`

The policy status code (integer). `0` indicates OK.

## Operations

### `get`

Queries the system for a policy matching `id`. Returns the full policy metadata if found, or `null` if the policy is not present.

- `id` *(required)*

### `set`

Deploys a policy to the system.

- `id` *(required)*
- `content` *(required)*

### `remove`

Removes a policy from the system by its `id`. Idempotent — if the policy is already absent, this is a no-op.

- `id` *(required)*

### `list`

Returns all App Control policies on the system with their full metadata.

*(No input properties required.)*

## Examples

### Deploy a compiled binary policy (base64)

```yaml
type: Microsoft.Windows/AppControl/Policy
properties:
  id: "BF61FE40-8929-4FDF-9EC2-F7A767717F0B"
  content: "AQAAAA..."
```

### Deploy a policy from XML

```yaml
type: Microsoft.Windows/AppControl/Policy
properties:
  id: "BF61FE40-8929-4FDF-9EC2-F7A767717F0B"
  content: |
    <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
      <PolicyID>{BF61FE40-8929-4FDF-9EC2-F7A767717F0B}</PolicyID>
      <!-- ... policy rules ... -->
    </SiPolicy>
```

### Query a specific policy

```yaml
type: Microsoft.Windows/AppControl/Policy
properties:
  id: "BF61FE40-8929-4FDF-9EC2-F7A767717F0B"
```

Returns (example):

```json
{
  "id": "{BF61FE40-8929-4FDF-9EC2-F7A767717F0B}",
  "baseId": "{BF61FE40-8929-4FDF-9EC2-F7A767717F0B}",
  "friendlyName": "AllowMicrosoft_WS2025_Audit",
  "version": "10.0.0.0",
  "isBasePolicy": true,
  "isDeployed": true,
  "isEffective": true,
  "isEnforced": false,
  "isAuthorized": true,
  "isSigned": false,
  "isSystemPolicy": false,
  "options": ["Enabled:Audit Mode", "Enabled:UMCI", "Enabled:Managed Installer"],
  "status": 0
}
```

### Remove a policy

```yaml
type: Microsoft.Windows/AppControl/Policy
properties:
  id: "{BF61FE40-8929-4FDF-9EC2-F7A767717F0B}"
```
