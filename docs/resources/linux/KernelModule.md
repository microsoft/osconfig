# Linux/KernelModule

Specifies a kernel module on the device. This resource can be used to load, unload, and check the status of kernel modules.

## Properties

### `name`

The name of the kernel module.

### `loaded`

Indicates whether the kernel module is currently loaded.

## Operations

### `get`

Checks whether the specified kernel module is currently loaded.

- `name`

### `set`

Loads or unloads the specified kernel module. If `loaded` is not specified, it defaults to `true` (load the module).

- `name`
- `loaded` (optional) - true by default

### `list`

Lists all currently loaded kernel modules.

## Examples

### Load a kernel module

```yaml
type: Linux/KernelModule
properties:
  name: "example"
  # loaded: true
```

### Unload a kernel module

```yaml
type: Linux/KernelModule
properties:
  name: "example"
  loaded: false
```

### Check if a kernel module is loaded

```yaml
type: Linux/KernelModule
properties:
  name: "example"
```
