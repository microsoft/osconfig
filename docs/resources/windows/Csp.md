# Microsoft.Windows/CSP

Specifies a Configuration Service Provider (CSP) setting on the device. CSP settings are identified by their OMA-URI path.

## Properties

### `path`

The OMA-URI path of the CSP setting. This can be specified in two forms:

- **String**: A full OMA-URI path (for example, `./Vendor/MSFT/Policy/Config/DeviceGuard/RequirePlatformSecurityFeatures`). The CSP name and relative path are automatically derived. If the path contains a `Config` segment, the corresponding `get` path is derived by replacing `Config` with `Result`, and vice versa.

- **Object**: An object with separate `get` and `set` paths for cases where the read and write paths differ:
  `yaml
  path:
    get: "Result/DeviceGuard/ConfigureSystemGuardLaunch"
    set: "Config/DeviceGuard/ConfigureSystemGuardLaunch"
  `

When using the object form, the `name` property is required.

### `name`

The CSP name (for example, `./Vendor/MSFT/Policy`). This is required when using the object form of `path`, and is automatically derived when using the string form.

### `type`

The data type of the CSP setting value. Must be one of:

- `string`
- `integer`
- `boolean`

### `value`

The value of the CSP setting.

## Operations

### `get`

Gets the current value of the specified CSP setting.

- `path`
- `type`
- `name` (optional)

### `set`

Sets the value of the specified CSP setting.

- `path`
- `type`
- `value`
- `name` (optional)

### `remove`

Removes the specified CSP setting.

- `path`
- `type`
- `name` (optional)

## Examples

### Set an integer CSP policy

```yaml
type: Microsoft.Windows/CSP
properties:
  path: "./Vendor/MSFT/Policy/Config/DeviceGuard/RequirePlatformSecurityFeatures"
  type: integer
  value: 3
```

### Set a string CSP setting

```yaml
type: Microsoft.Windows/CSP
properties:
  path: "./Vendor/MSFT/LAPS/Policies/AutomaticAccountManagementNameOrPrefix"
  type: string
  value: "ExampleValue"
```

### Set a CSP setting with separate get/set paths

```yaml
type: Microsoft.Windows/CSP
properties:
  name: "./Vendor/MSFT/Policy"
  path:
    get: "Result/DeviceGuard/ConfigureSystemGuardLaunch"
    set: "Config/DeviceGuard/ConfigureSystemGuardLaunch"
  type: integer
  value: 1
```
