<!--
Thanks for contributing to GXC-CORE.

If this touches consensus — anything that changes which blocks or transactions
are considered valid — say so explicitly below. Consensus changes need test
coverage that demonstrates both the accepting and the rejecting case.
-->

## What this changes

<!-- A short description of the change and why it is needed. -->

## Consensus impact

<!-- Delete whichever does not apply. -->

- [ ] No consensus impact — node-local only (API, tooling, docs, performance)
- [ ] Changes block or transaction validity (explain below)

## How it was tested

<!--
Which tests cover this? New tests added? Paste the relevant `ctest` output.
For consensus changes, show that invalid inputs are rejected, not just that
valid ones are accepted.
-->

```
$ cmake -S . -B build -DBUILD_TESTS=ON && cmake --build build
$ cd build && ctest --output-on-failure
```

## Checklist

- [ ] Builds clean under `-Wall -Wextra -Wpedantic`
- [ ] `ctest` passes
- [ ] New behaviour has tests covering the rejecting path, not only the happy path
- [ ] Documentation updated if behaviour or interfaces changed
