# Microsoft.Windows/AuditPolicy

Specifies an advanced audit policy subcategory setting on the device. Each instance of this resource represents a single audit policy subcategory identified by its GUID.

## Properties

### `subcategory`

The GUID of the audit policy subcategory (for example, `{0CCE9232-69AE-11D9-BED3-505054503030}`).

### `value`

The audit policy setting value:

- `0` - No auditing
- `1` - Success
- `2` - Failure
- `3` - Success and Failure

## Operations

### `get`

Gets the current audit policy setting for the specified subcategory.

- `subcategory`

### `set`

Sets the audit policy setting for the specified subcategory.

- `subcategory`
- `value`

## Examples

### Audit success events for a subcategory

```yaml
type: Microsoft.Windows/AuditPolicy
properties:
  subcategory: "{0CCE9232-69AE-11D9-BED3-505054503030}"
  value: 1
```

### Audit success and failure events

```yaml
type: Microsoft.Windows/AuditPolicy
properties:
  subcategory: "{0CCE9215-69AE-11D9-BED3-505054503030}"
  value: 3
```

### Disable auditing for a subcategory

```yaml
type: Microsoft.Windows/AuditPolicy
properties:
  subcategory: "{0CCE9213-69AE-11D9-BED3-505054503030}"
  value: 0
```
