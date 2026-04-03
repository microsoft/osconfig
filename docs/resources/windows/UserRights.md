# Microsoft.Windows/UserRightsAssignment

Specifies a user rights assignment (privilege) on the device. Each instance of this resource represents a single user right and the list of accounts that are assigned to it.

## Properties

### `name`

The name of the user right. Must be one of the following:

- `SeAssignPrimaryTokenPrivilege`
- `SeAuditPrivilege`
- `SeBackupPrivilege`
- `SeBatchLogonRight`
- `SeChangeNotifyPrivilege`
- `SeCreateGlobalPrivilege`
- `SeCreatePagefilePrivilege`
- `SeCreatePermanentPrivilege`
- `SeCreateSymbolicLinkPrivilege`
- `SeCreateTokenPrivilege`
- `SeDebugPrivilege`
- `SeDelegateSessionUserImpersonatePrivilege`
- `SeDenyBatchLogonRight`
- `SeDenyInteractiveLogonRight`
- `SeDenyNetworkLogonRight`
- `SeDenyRemoteInteractiveLogonRight`
- `SeDenyServiceLogonRight`
- `SeEnableDelegationPrivilege`
- `SeImpersonatePrivilege`
- `SeIncreaseBasePriorityPrivilege`
- `SeIncreaseQuotaPrivilege`
- `SeIncreaseWorkingSetPrivilege`
- `SeInteractiveLogonRight`
- `SeLoadDriverPrivilege`
- `SeLockMemoryPrivilege`
- `SeMachineAccountPrivilege`
- `SeManageVolumePrivilege`
- `SeNetworkLogonRight`
- `SeProfileSingleProcessPrivilege`
- `SeRelabelPrivilege`
- `SeRemoteInteractiveLogonRight`
- `SeRemoteShutdownPrivilege`
- `SeRestorePrivilege`
- `SeSecurityPrivilege`
- `SeServiceLogonRight`
- `SeShutdownPrivilege`
- `SeSyncAgentPrivilege`
- `SeSystemEnvironmentPrivilege`
- `SeSystemProfilePrivilege`
- `SeSystemtimePrivilege`
- `SeTakeOwnershipPrivilege`
- `SeTcbPrivilege`
- `SeTimeZonePrivilege`
- `SeTrustedCredManAccessPrivilege`
- `SeUndockPrivilege`

### `value`

An array of account SID strings that are assigned the user right. SIDs are prefixed with `*` (for example, `*S-1-5-32-544`).

## Operations

### `get`

Gets the list of accounts assigned to the specified user right.

- `name`

### `set`

Sets the list of accounts assigned to the specified user right. Accounts not in the provided list will be removed, and accounts in the list that are not currently assigned will be added.

- `name`
- `value`

## Examples

### Assign backup privilege

```yaml
type: Microsoft.Windows/UserRightsAssignment
properties:
  name: SeBackupPrivilege
  value:
    - "*S-1-5-32-544"
    - "*S-1-5-32-551"
    - "*S-1-5-32-549"
```

### Get accounts with debug privilege

```yaml
type: Microsoft.Windows/UserRightsAssignment
properties:
  name: SeDebugPrivilege
```
