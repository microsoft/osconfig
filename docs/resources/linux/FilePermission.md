# Linux/FilePermission

Specifies the permissions, owner, and group of a file or set of files on the device. The path property supports glob patterns for matching multiple files.

## Properties

### `path`

The path to the file. Supports glob patterns (for example, `/etc/ssh/*`).

### `mode`

The file permission mode in octal format (for example, `644`, `0755`). Only the user/group/other permission bits are used.

### `owner`

The file owner. Can be a username (string) or a numeric user ID.

### `group`

The file group. Can be a group name (string) or a numeric group ID.

### `exists`

Indicates whether the file exists.

## Operations

### `get`

Gets the file permission information, including the mode, owner, group, and whether the file exists.

- `path`

### `set`

Sets the file permissions, owner, and/or group. If the path is a glob pattern, the permissions are applied to all matching files. Only specified properties are modified.

- `path`
- `mode` (optional)
- `owner` (optional)
- `group` (optional)

## Examples

### Set file permissions

```yaml
type: Linux/FilePermission
properties:
  path: "/tmp/example.txt"
  mode: "644"
  owner: "root"
  group: "root"
```

### Set permissions using numeric IDs

```yaml
type: Linux/FilePermission
properties:
  path: "/tmp/example.txt"
  mode: "0600"
  owner: 1000
  group: 1000
```

### Get file permissions

```yaml
type: Linux/FilePermission
properties:
  path: "/tmp/example.txt"
```
