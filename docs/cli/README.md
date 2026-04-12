# OSConfig CLI

OSConfig command-line interface (CLI) is a cross-platform tool for managing system configuration using the OSConfig platform. Use the CLI to apply configurations, view resources, and manage namespaces across Windows and Linux systems.

OSConfig manages configuration through **resources** (the actual configuration items like registry settings, file permissions, and policies) organized within **namespaces** (logical containers that group related configurations by purpose or system type). When no namespace is specified in commands, the `default` namespace is used automatically.

See [Resources](../resources/README.md) for available configuration options.

## Common commands

| Command | Description |
| ------- | ----------- |
| `oscfg apply` | Apply configuration from a file |
| `oscfg get` | View configuration resources and namespaces |
| `oscfg create` | Create new namespaces |
| `oscfg delete` | Delete resources or namespaces |
| `oscfg exec` | Execute resource operations directly |

## Examples

### Apply configurations

Apply a configuration file to the system:

```bash
oscfg apply -f config.yaml
```

Apply a configuration file to the system in a specific namespace:

```bash
oscfg apply -f config.json -n mybaseline
```

### View namespaces and resources

Get all namespaces:

```bash
oscfg get namespace
```

Get all resources in the default namespace:

```bash
oscfg get resource
```

Get a named resource in a specific namespace:

```bash
oscfg get resource --name "minimum-password-length" -n mybaseline
```

### Manage namespaces

Create a new namespace:

```bash
oscfg create namespace mybaseline
```

Delete a namespace:

```bash
oscfg delete namespace mybaseline
```

### Manage resources

Delete a specific resource:

```bash
oscfg delete resource --name "minimum-password-length" -n mybaseline
```

### Execute resource operations

Get a registry value:

```bash
oscfg exec resource --mode get --type "Microsoft.Windows/Registry" --properties "keyPath=HKLM:\\Software\\MyApp,valueName=Version"
```

Set a registry value:

```bash
oscfg exec resource --mode set --type "Microsoft.Windows/Registry" --properties "keyPath=HKLM:\\Software\\MyApp,valueName=AppName,value=MyApplication,valueType=REG_SZ"
```

Get file permissions:

```bash
oscfg exec resource --mode get --type "Linux/FilePermission" --properties "path=/etc/shadow"
```

### Output formatting

Get resources with JSON output:

```bash
oscfg get resource --output json
```

Enable debug logging:

```bash
oscfg get resource --debug
```

## Getting help

Get help for any command:

```bash
oscfg --help
oscfg apply --help
...
```
