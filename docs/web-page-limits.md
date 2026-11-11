# The in-browser scanner: what it does and does not do

[`web/`](../web) is a static page that runs the scanner in the browser. The root [README](../README.md) says how to build and serve it. The page runs the same rules as the command line and its output matches `--json` byte for byte, with these limits:

- Code nested more than about 2000 levels deep runs the in-browser build out of stack. The page says so and points to the command line.
- Pasted source is a single file with no `Cargo.toml`, so PF022, which reads the build profile, stays silent on it.
- It does not run the sandbox exploits, check a deployed contract, or read private repositories.
- GitHub's listing requests (two per scan) go to api.github.com, which allows 60 an hour per IP without a sign-in.
- Browsers will not load WebAssembly from `file://`, so open the page through `make -C web serve`.
- The headline is a count of pattern matches by severity, never a verdict.

More in [web/README.md](../web/README.md).
