# Contributing

Use Node.js 22 or newer and npm for local development:

```sh
npm ci
npm test
npx --no-install tsc --noEmit
npm run dev
```

The development server binds to localhost:4173. Run `npm run build` again after
source changes; the small development server does not rebuild automatically.

Keep changes focused. Preserve exact entropy calculations, unbiased sampling,
dictionary provenance, character exclusions, browser privacy and accessibility
behavior. Dictionary inputs and reports under `data/` are pinned; do not change
them or their hashes without reviewing the intended data change.

`npm test` builds the application and runs the source regression tests. Optional
`tests/browser-*.mjs` suites require Playwright and Microsoft Edge outside this
package. Set `KEYSMITH_PLAYWRIGHT_MODULE` to the installed Playwright module path
and `KEYSMITH_BROWSER_PATH` to the Edge executable when those are not found by
default. These variables are for optional browser tests, not the Docker runtime. Browser screenshots are test artifacts, never
part of a source release. Use public fixtures, not real generated passwords.

Do not commit credentials, TLS material, `.env`, logs, dependencies, generated
`dist/`, or test artifacts. See SECURITY.md for confidential reporting and LICENSE
plus data/NOTICE.md for application and dictionary licensing.
