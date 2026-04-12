# FirmwareResource

Retrieves information about the firmware resources in the machine's ESRT table. This resource is read-only.

## Properties

### `firmwareClass`

The firmware class GUID of the firmware resource.

### `firmwareVersion`

The firmware version of the firmware resource.

### `lowestSupportedVersion`

The lowest supported firmware version of the firmware resource.

### `capsuleFlags`

The capsule flags of the firmware resource.

## Operations

### `get`

Gets the firmware resource information for a firmware resource with the specified firmware class GUID.

- `firmwareClass`

### `list`

Gets the firmware resource information for all firmware resources in the machine's ESRT table.

## Examples

### Get firmware information by class GUID

```yaml
type: FirmwareResource
properties:
  firmwareClass: "12345678-1234-1234-1234-123456789012"
```
