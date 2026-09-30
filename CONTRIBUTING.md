# Contributing

## The easiest PR: add a case title

Add a line to `internal/phrases/titles.txt`. It must start with "The" and fit in 32 characters. A test checks both.

## The most useful PR: add a lesson

`its-always-dns why` teaches one real DNS failure mode at a time. Lessons live in `internal/phrases/why.txt`, one per line, as `title | explanation`. The explanation must be true and at most two sentences. Link a source in the PR description.

## A new check

Checks live in `internal/checks`. Each returns findings with a severity:

- `fail` means this layer is broken and would stop a real request.
- `warn` means it works but something is wrong or slow.
- `info` is context, including checks that were skipped or blocked.

Tests must not touch the internet. Use the fake DNS server in `fake_test.go` and `httptest` servers, like the existing tests.

If output changes, regenerate the golden files and read the diff:

```
go test ./internal/render -update
git diff internal/render/testdata
```

## The one rule

The narrative always concludes "It was DNS." The evidence must always tell the truth.
