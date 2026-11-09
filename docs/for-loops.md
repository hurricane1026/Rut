# For Loops

`for` loop syntax was removed from the language surface. The design notes still
reference this page as the historical record for the retired static-loop
experiment.

Current code should not use `for` loops in Rut source. See `docs/design-goals.md`
and the active front-end tests for the supported control-flow forms.

For complete-buffer parser work, [bounded parsing](bounded-parsing.md) provides
`collectBytes` with a compile-time step function and literal work limit. This
does not restore the retired static `for` syntax.
