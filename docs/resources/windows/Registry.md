# Microsoft.Windows/Registry

This resource represents a registry key and value in the Windows registry. It allows you to get and set registry values.

## Properties

### `keyPath`

 The registry path to the registry key. For example, `HKEY_CURRENT_USER:\Software\MyApp`.

 The hive is included in the path and can be in the following forms:

- `HKEY_LOCAL_MACHINE:\Software\MyApp`
- `HKLM:\Software\MyApp`

### `valueName`

 The registry value name. For example, `MyValue`.

### `valueType`

 The registry value type. If the value type is not specified, it will be inferred from the value data.

- `REG_SZ` - null-terminated string
- `REG_DWORD` - A 32-bit unsigned integer
- `REG_QWORD` - A 64-bit unsigned integer
- `REG_BINARY` - Binary (data represented as a base64 string)
- `REG_MULTI_SZ` - An array of null-terminated strings (data represented as a JSON array of strings)

### `value`

 The registry value data.

## Operations

### `get`

Gets the registry value specified by the `keyPath` and `valueName`. If `valueType` is specified, it will be used to determine the type of the value data. If `valueType` is not specified, it will be inferred from the value data.

- `keyPath`
- `valueName`
- `valueType` (optional)

### `set`

Sets the registry value specified by the `keyPath` and `valueName` to the specified `value`. If `valueType` is specified, it will be used to determine the type of the value data and the resource will attempt to coerce the data to the specified type. If `valueType` is not specified, it will be inferred from the value data.

- `keyPath`
- `valueName`
- `valueType` (optional)
- `value`

## Examples

### Set a registry value

### Get a registry value

### Check if a registry key exists
