# DeviceInfo

Specifies properties of the device, such as manufacturer, product name, and BIOS information. This resource is read-only.

## Properties

### `systemManufacturer`

The value in the manufacturer field identifies the company brand name under which the device is marketed to the end user (for example, a brand name or logo imprinted on the device).

### `systemProductName`

The value in the product name field identifies Company's specific model of device, without enumerating configuration variance (for example, processor, memory, and storage variance). There are often several product names that are specific to model in a specific family, although no more than a dozen or so.

### `biosVersion`

The system BIOS version number. This value is a free-form string that may contain Core and OEM version information.

### `biosReleaseDate`

The date string, if supplied, is in either `mm/dd/yy` or `mm/dd/yyyy` format. If the year portion of the string is two digits, the year is assumed to be `19yy`.

## Operations

### `get`

Gets the device information. This operation is best effort and not all properties may be returned on all platforms.

- `systemManufacturer` (optional)
- `systemProductName` (optional)
- `biosVersion` (optional)
- `biosReleaseDate` (optional)

### `list`

Lists all device information.

## Examples

### Get device information

```yaml
name: Get device information
type: DeviceInfo
properties:
  # Read-only properties, no input required
```
