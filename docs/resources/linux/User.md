# Linux/User

Specifies a local user account on the device.

## Properties

### `name`

The name of the user account.

### `gid`

The primary group ID of the user account.

## Operations

### `set`

Sets the primary group ID of the specified user account.

- `name`
- `gid` (optional)

## Examples

### Set the primary group of a user

```yaml
type: Linux/User
properties:
  name: "root"
  gid: 0
```
