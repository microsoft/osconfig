# File

Specifies a file on the device. This resource can be used to create, modify, or delete a file, as well as to check if a file exists and read its content.

## Properties

### `path`

The path to the file.

### `content`

The content of the file.
This property is required when creating or updating a file.

### `exists`

Indicates whether the file exists.

When creating a file, setting this property to `true` will create the file if it does not exist. Setting this property to `false` will delete the file if it exists.

## Operations

### `get`

Gets the file information, including whether the file exists and its content if it does.

- `path`

### `set`

Sets the file content and existence.

- `path`
- `content` (optional)
- `exists` (optional) - true by default

## Examples

### Create a file with specific content

```yaml
type: File
properties:
  path: "/tmp/example.txt"
  content: "Hello, World!"
  # exists: true
```

### Check if a file exists

```yaml
type: File
properties:
  path: "/tmp/example.txt"
```
