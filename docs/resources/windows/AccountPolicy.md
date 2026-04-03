# Microsoft.Windows/AccountPolicy

Specifies a local account policy setting on the device. Each instance of this resource represents a single named policy and its value.

## Properties

### `name`

The name of the account policy. Must be one of the following:

- `MinimumPasswordAge` - Minimum password age in days
- `MaximumPasswordAge` - Maximum password age in days
- `MinimumPasswordLength` - Minimum password length
- `PasswordHistoryLength` - Number of passwords remembered
- `EnforcePasswordComplexity` - Whether password complexity requirements are enforced
- `EnablePasswordReversibleEncryption` - Whether passwords are stored using reversible encryption
- `AdministratorAccountName` - Name of the local administrator account
- `GuestAccountName` - Name of the local guest account
- `EnableAdministratorAccount` - Whether the local administrator account is enabled
- `EnableGuestAccount` - Whether the local guest account is enabled
- `LockoutThreshold` - Number of failed logon attempts before lockout
- `LockoutDuration` - Lockout duration in minutes
- `LockoutReset` - Time in minutes before the lockout counter resets
- `EnableAnonymousNameTranslation` - Whether anonymous SID/name translation is allowed

### `value`

The value of the account policy. Depending on the policy, the value can be one of the following types:

- `integer` for age/length/threshold/duration settings
- `boolean` for enable/enforce settings
- `string` for account name settings

## Operations

### `get`

Gets the current value of the specified account policy.

- `name`

### `set`

Sets the value of the specified account policy.

- `name`
- `value`

## Examples

### Set minimum password length

```yaml
type: Microsoft.Windows/AccountPolicy
properties:
  name: MinimumPasswordLength
  value: 14
```

### Enable password complexity

```yaml
type: Microsoft.Windows/AccountPolicy
properties:
  name: EnforcePasswordComplexity
  value: true
```

### Rename the administrator account

```yaml
type: Microsoft.Windows/AccountPolicy
properties:
  name: AdministratorAccountName
  value: "MyAdmin"
```
