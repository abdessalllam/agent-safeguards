# Contributing

## Ground rules

- Standard library only. No runtime dependencies.
- Every user-facing message comes from `locales/en.json`. Add the key there and call `message("your.key")`. Do not write message text in code.
- Every visible block must say what to do instead. A refusal with no rewrite is a bug.
- Build any secret-shaped sample value by concatenation, so scanners do not flag the repository.
- Avoid the em dash character in code, docs, and messages. Use a comma, colon, period, or parentheses.

## Checks

Each tool has a built-in policy self-test. The `blocked` and `allowed` lists inside `_self_test` in `bin/safe-tool` and `bin/delete-guard` are the regression record, so add every command that motivates a change to the matching list.

For any change to a guard:

1. Add the command to the blocked or allowed list in `_self_test` first and watch the self-test fail.
2. Change the guard until it passes.
3. Run both self-tests from a Git repository outside a temp folder:

```sh
python3 -I bin/safe-tool self-test
python3 -I bin/delete-guard self-test
```

For a change to a manifest or hook file, also run `claude plugin validate . --strict`.

## Adding a language

Copy `locales/en.json` to `locales/<code>.json`, translate the values, and keep every key and every `{placeholder}`.

## Pull requests

Keep each pull request to one behavior change. Describe the command that motivated it and name the self-test case that covers it.
