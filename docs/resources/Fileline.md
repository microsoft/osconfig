# FileLine

Specifies a line-level find and replace operation on a file. This resource uses regex patterns to find lines in a file and optionally replace or append content.

## Properties

### `path`

The path to the file.

### `find`

The regex pattern used to find the line in the file.

### `replace`

The replacement string to replace the found line.

If this property is not specified, it is the same as setting replace to an empty string, which will remove the line from the file.

### `append`

Whether the replacement string should be appended to the end of the file if the regex pattern is not found.

Defaults to `false`.

### `ignoreCase`

Whether the regex pattern matching should ignore case.

Defaults to `false`.

### `exists`

Indicates whether the pattern matches a line in the file.

## Operations

### `get`

Checks if the regex pattern matches a line in the file.

- `path`
- `find`
- `ignoreCase` (optional)

### `set`

Searches the file one line at a time for matches and replaces them with the replacement string. If no matches are found and `append` is `true`, the replacement string will be appended to the end of the file.

- `path`
- `find`
- `ignoreCase` (optional)
- `replace` (optional)
- `append` (optional)

## Examples

### Check if a line exists in a file

```yaml
type: FileLine
properties:
  path: "/etc/issue.net"
  find: "\\\\m"
```

### Replace a line in a file, appending if not found

```yaml
type: FileLine
properties:
  path: "/etc/security/limits.conf"
  find: "^\\* hard core 0$"
  replace: "* hard core 0"
  append: true
```
