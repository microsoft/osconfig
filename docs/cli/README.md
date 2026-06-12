# OSConfig CLI (Preview)

OSConfig command-line interface (CLI) is a cross-platform tool for managing system configuration using the OSConfig platform. Use the CLI to apply configurations, view resources, and manage namespaces across Windows and Linux systems.

OSConfig manages configuration through **resources** (the actual configuration items like registry settings, file permissions, and policies) organized within **namespaces** (logical containers that group related configurations by purpose or system type). When no namespace is specified in commands, the `default` namespace is used automatically.

See [Resources](../resources/README.md) for available configuration options.

## Installation

> **Note**: The following installation instructions are examples for some environments. You may need to adapt these steps based on your specific environment.

### Windows (10.0.17763.0 or later)

1. Install the OSConfig CLI:

    1. For 10.0.17763.0 and later, use the [WinGet](https://learn.microsoft.com/en-us/windows/package-manager/winget/) package manager to install the OSConfig CLI:

        ```pwsh
        winget install Microsoft.OSConfig
        ```

### Red Hat Enterprise Linux (RHEL) and other variants

1. Add the Microsoft package repository to your system (replace `[VERSION]` with your RHEL version, e.g., 8 or 9):

    1. For the `dnf` package manager, use the following command:

        ```bash
        sudo dnf config-manager --add-repo https://packages.microsoft.com/config/rhel/[VERSION]/insiders-fast.repo
        ```

    1. For the `yum` package manager, use the following command:

        ```bash
        sudo yum-config-manager --add-repo=https://packages.microsoft.com/config/rhel/[VERSION]/insiders-fast.repo
        ```

1. Import the Microsoft GPG public key:

    ```bash
    sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
    ```

1. Update the package index:

    1. For the `dnf` package manager, use the following command:

        ```bash
        sudo dnf clean all
        sudo dnf makecache
        ```

    1. For the `yum` package manager, use the following command:

        ```bash
        sudo yum clean all
        sudo yum makecache
        ```

1. Install the OSConfig CLI:

    1. For the `dnf` package manager, use the following command:

        ```bash
        sudo dnf install oscfg
        ```

    1. For the `yum` package manager, use the following command:

        ```bash
        sudo yum install oscfg
        ```

### Ubuntu

1. Add the Microsoft package repository to your system (replace `[VERSION]` with your Ubuntu version, e.g., 20.04, 22.04, or 24.04):

    ```bash
    curl -o microsoft-insiders-fast.list https://packages.microsoft.com/config/ubuntu/[VERSION]/insiders-fast.list
    sudo mv ./microsoft-insiders-fast.list /etc/apt/sources.list.d/microsoft-insiders-fast.list
    ```

1. Import the Microsoft GPG public key:

    1. For Ubuntu 22.04 and earlier, use the following command:

        ```bash
        curl -sSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/microsoft.gpg > /dev/null
        sudo chmod o+r /etc/apt/trusted.gpg.d/microsoft.gpg
        ```

    1. For Ubuntu 24.04 and later, use the following command:

        ```bash
        curl -sSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | sudo tee /usr/share/keyrings/microsoft-prod.gpg > /dev/null
        sudo chmod o+r /usr/share/keyrings/microsoft-prod.gpg
        ```

1. Update the package index:

    ```bash
    sudo apt update
    ```

1. Install the OSConfig CLI:

    ```bash
    sudo apt install oscfg
    ```

### Azure Linux

1. Add the Microsoft repository configuration:

    ```bash
    sudo tee /etc/yum.repos.d/oscfg-preview.repo > /dev/null <<EOF
    [oscfg-preview]
    name=oscfg-preview
    baseurl=https://packages.microsoft.com/yumrepos/oscfg-preview
    enabled=1
    gpgcheck=1
    gpgkey=https://packages.microsoft.com/keys/microsoft.asc
    EOF
    ```

1. Update the package index:

    ```bash
    sudo tdnf clean all
    sudo tdnf makecache
    ```

1. Install the OSConfig CLI:

    ```bash
    sudo tdnf install oscfg
    ```

## Common commands

| Command | Description |
| ------- | ----------- |
| `oscfg apply` | Apply configuration from a file |
| `oscfg get` | View configuration resources and namespaces |
| `oscfg create` | Create new namespaces |
| `oscfg delete` | Delete resources or namespaces |
| `oscfg exec` | Execute resource operations directly |
| `oscfg reconcile` | Resolve cross-namespace conflicts and re-apply the winning resources |

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

### Conflict resolution

The `oscfg reconcile` command detects and resolves conflicts that occur when the same resource (e.g., the same registry value or the same file path) is declared in more than one namespace. `reconcile` computes the *winning* set of resources and re-applies them to the system.

Reconcile every namespace on the host:

```bash
oscfg reconcile
```

Preview the resolved configuration without changing system state (no resources are applied):

```bash
oscfg reconcile --dry-run
```

#### Configuration priority

Any configuration document can specify an optional `priority` field which is used to determine the resource priority during reconciliation. By default, the priority is set to `0`.

```yaml
$schema: https://aka.ms/osc/schemas/prerelease/document.json
priority: 200
resources:
  - name: MinimumPasswordLength
    type: Microsoft.Windows/AccountPolicy
    properties:
      name: MinimumPasswordLength
      value: 14
```

#### Priority evaluation

Each resource instance resolves to a stable, unique *identity* based on its type and a selection of its properties. If two or more resource share the same identity, the *winner* is determined using the priority of the resource's namespace.

Each resource in the report is tagged with one of three statuses:

| Status | Meaning |
| ------ | ------- |
| `selected` | This resource won over other conflicting resources and has been selected to be applied. |
| `overridden` | This resource lost to a higher-priority resource in another namespace with the same identity and will not be applied. |
| `indeterminate` | The resource could not compute an identity or does not support conflict resolution, so it cannot participate in conflict resolution and is reported as-is. Such resources are not re-applied during reconciliation. |

A duplicate resource identity *within* a single namespace is treated as a configuration error and causes `reconcile` to fail.

### Output formatting

Get resources with JSON output:

```bash
oscfg get resource --output json
```

Enable debug logging:

```bash
oscfg get resource --debug
```

## Logging

| Platform | Path |
| -------- | ---- |
| Linux | `/var/log/oscfg.log` |
| Windows | `%PROGRAMDATA%\Microsoft\OSConfig\log\oscfg.log` |

Set the `OSCONFIG_LOG_DIR` environment variable to write the log to a different directory.

## Pre-built Manifests

Use pre-built configuration manifests to quickly configure your systems according to security best practices (e.g., Azure Security Baseline for Windows). See the [manifests](../../manifests/) directory for all available options.

## Getting help

Get help for any command:

```bash
oscfg --help
oscfg apply --help
...
```
