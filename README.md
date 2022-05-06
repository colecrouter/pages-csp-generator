# Pages-CSP-Generator
Automatically generate [hashes](https://content-security-policy.com/hash/) and [nonces](https://content-security-policy.com/nonce/) along with [Content Security Policy](https://content-security-policy.com/) compliant headers for static Cloudflare Pages sites.

<br />

### What if my Page isn't Static?
There's no good way to parse obfuscated JS for assets of unknown types. Especially if SSR is used, it can be impossible. If you're willing to put in a little work, you can [make it work](#"oh-no-my-assets-arent-loading"), but it won't always be worth the trouble, especially if framework-specific plugins exist.

<br />

### What it Does
Using [HTMLRewriter](https://developers.cloudflare.com/workers/runtime-apis/html-rewriter), it:
- Looks for any existing headers/`<meta http-equiv="Content-Security-Policy">`
- Looks for any inline scripts/stylesheets that need [hashes](https://content-security-policy.com/hash/)/[nonces](https://content-security-policy.com/nonce/)
- Looks for any inline elements (such as `<img>`, `<iframe>`, etc.) that contain URLs
- Scans through any linked web-app-manifests and stylesheets that contain images
- Injects the headers into the request, automatically, per page

> This project is new, so there are some features/directives that haven't been addressed yet. See below for how to override default behaviour.

<br />

### How to Use
```sh
npm i @mexican-man/pages-csp-generator
```
Import it as middleware in your `_middleware.ts`:
```ts
import { InjectCSP } from '@mexican-man/pages-csp-generator';

export const onRequestGet = [InjectCSP({ /* config here */ })];
```
<br />

### Configuration


#### `InlineMethod`: `'nonce'` |  `'sha256'` | `'sha384'` | `'sha512'` (default: `'nonce'`)
How to handle inline scripts/styles.

<hr />

#### `InjectionMethod`: `'headers'` | `'meta-tags'` (default: `'headers'`)
How to serve the CSP directive to the browser.

<hr />

#### `UseSelf`: `boolean` (default: `true`)
Allow the use of the `'self'` keyword when generating headers.

<hr />

#### `ScanExternal`: `boolean` (default: `false`)
By default, only local assets (ony css, manifests, for now) get scanned for URLs. You can override this behaviour to work with non-local files as well, but performance can tank dramatically.

<br />

### A Quick Word About Performance
Execution time is usually quite fast, with larger pages taking around 30-40ms to process. Some more optimization could be added via caching.

<br />

### "Oh no, my Assets Aren't Loading!"
If you load any assets via Javascript, there's a good chance you'll need to do some extra work to let the package know what it needs to add.

There are three ways you can manually add assets:
1. Add a `<link>` element in your `<head>` [(`preload`, `prefetch`, `prerender`, etc. all work)](https://developer.mozilla.org/en-US/docs/Web/HTML/Link_types/preload)
1. Add a [`<meta http-equiv="Content-Security-Policy" content="...">` to your `<head>` and it will get picked up automatically
1. Adding CSP headers programatically (or with a `_headers` file), they will also get picked up.

<small>[Guide to CSP headers/formatting*](https://content-security-policy.com/)</small>

<br />

If you're using something like web-components, or you really like using the `style="..."` attribute, you can always add `"unsafe-inline"`, or any other [valid value](https://content-security-policy.com/#source_list).


Naturally, some assets don't fit within our CSP-formatting needs. Assets such as Google Fonts will import a `.woff` that changes URL each request, so you would manually need to add `https://fonts.gstatic.com` to `font-src`.

> If you find a type of resource that isn't being handled properly, please PR or open an issue.
