# Pages-CSP-Generator
The goal of this package is to provide a simple automated way to generate [Content Security Policy](https://content-security-policy.com/) compliant headers for your Cloudflare Pages site at runtime. The primary goal is to automate [hashing](https://content-security-policy.com/hash/) and [nonces](https://content-security-policy.com/nonce/), but it will also do configurable scanning of your files to include anything else included in stylesheets, etc.

### What it Does
Using [HTMLRewriter](https://developers.cloudflare.com/workers/runtime-apis/html-rewriter), it attempts a surface-level scan for any inline scripts/stylesheets, as well as any imported assets that would need to be allowed.
It also does a one-level deep search into linked `.js` and `.css` files (and inline scripts, too)  to look for any absolute URLs that might need to be allowed (and caches them). 

> This is WIP, some testing/improvement/additions could be done on lots of file types.

### How to Use
Add this repository as a submodule:
```
git submodule add https://github.com/Mexican-Man/pages-csp-generator
```
– or copy the `src/*` from this repository into your project.

Import it as middleware in your `index.ts` or `_middleware.ts`:
```ts
export const onRequestGet = [InjectCSP({ InlineMethod: "nonce", InjectionMethod: "meta-tags" })];
```
<br />
Initialization requires some basic configuration:

<hr />

#### *`InlineMethod`: `'nonce'` |  `'sha256'` | `'sha384'` | `'sha512'`
How to handle inline scripts/styles.

<hr />

#### *`InjectionMethod`: `'headers'` | `meta-tags'`
How to serve the CSP directive to the browser.

<hr />

#### *`CacheMethod`: `'none'` | `'localhost'` | `'all'`
When fetching the contents of files, the results can be cached for increased performance. None ensures each page is scraped freshly, ensuring the CSP sent is up-to-date for that page. Local is safe for pages that don't changed dynamically. All will cache all requests, including external ones. This means that your page **will** break if one of your external resources changes its dependencies/assets.

<hr />

#### `ScanExternal`: `boolean` (default: `false`)
By default, only local Javascript files get scanned for URLs. You can override this behaviour to work with external files as well, but performance can tank dramatically, unless combined with `CacheMethod: 'all'`.

<hr />

#### `RecurseJS`: `boolean` (default: `false`)
If true, Javascript files will recurse into any other referenced URLs/modules. This behaviour is still experimental, as a proper Javascript intepreter is in order, or maybe be omitted entirely, as it gets quite complicated 😮‍💨.

<br />

It's worth noting if you don't know already: [nonce](https://content-security-policy.com/nonce/) takes less performance, but changes the page on each request. [hashing](https://content-security-policy.com/hash/) requires more performance, but only changes when the components themselves change.

There's virtually no advantage to using `headers` over `meta-tags` and vice-versa.

### A Word About Performance
Execution time is usually quite fast, with larger pages taking around 80ms to process. That being said, if you're running a large page, I would recommend (if possible) using `CacheMethod: 'all'` and disabling everything else. Alternatively, you can run this middleware in development only, and copy/adjust the headers into production.

### "Oh no, my Assets Aren't Loading!"
If you find a type of resource that isn't being handled properly, please PR or open an issue.

Naturally, some assets don't fit within our CSP-formatting needs. Assets such as Google Fonts will import a `.woff` that changes URL each request, so you would manually need to add `https://fonts.gstatic.com` to `font-src`.

There are three ways you can manually add assets. Firstly, all `<link>` elements are added, so you can add your assets to the `<head>` as a `preload`, `prefetch`, `prerender`, etc. Second, you can manually add a `<meta http-equiv="Content-Security-Policy" content="...">` to your `<head>` and it will get picked up automatically (works with `meta-tags` *and* `headers`).

As well, if you are already adding headers programatically, you can add CSP headers to the page response before this middleware runs, and those headers will be included.

Lastly, you can preload your content using `<meta>` tags, and it will get processed.

If you're using something like web-components, or you really like using the `style="..."` attribute, you can always add `"unsafe-inline"`, or any other [valid value](https://content-security-policy.com/#source_list).
