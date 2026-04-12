# Test

Evaluates an inner resource and evaluates the result to generate a compliance status and reason.

## Properties

### `resource`

The inner resource to be evaluated. This is a required property.

### `expression`

A [CEL](https://opensource.google/projects/cel) expression to evaluate the inner resource. The inner resource's properties are available as variables in the expression.

### `template`

A string template that can be used to generate a human readable reason for the compliance status. The inner resource's properties are available as variables in the template using single braces (for example, `{path}`).

## `compliance`

- `status` - The compliance status of the resource - `compliant` or `noncompliant`
- `reason` - A human readable reason for the compliance status, generated from the `template` property if specified.

## Operations

### `get`

Evaluates the inner resource then evaluates the expression or schema to determine the compliance status and reason.

- `resource`
- `expression`
- `template` (optional)

### `set`

_Pass-through to the inner resource's set operation._

### `remove`

_Pass-through to the inner resource's remove operation._

## Examples

### Check if a file contains a specific line

```yaml
type: Test
properties:
  resource:
    type: FileLine
    properties:
      path: /etc/example.conf
      find: example_setting=true
  expression: "exists"
  template: The file {path} must contain the line 'example_setting=true'
```
