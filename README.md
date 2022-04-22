# Pages-CSP-Generator
The goal of this package is to provide a simple automated way to generate [Content Security Policy](https://content-security-policy.com/) headers for your Cloudflare Pages site at runtime. Ideally, you would use your framework to build a CSP for you, or make one on your own beforehand, but this is a lazy-man's approach to the problem.

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
export const onRequestGet = [InjectCSP({ inline: "nonce", method: "meta-tags" })];
```
<br />
Initialization requires some basic configuration:

<hr />

#### `inline`: `nonce` |  `sha256` | `sha384` | `sha512`
How to handle inline scripts/styles.

<hr />

#### `method`: `headers` | `meta-tags`
How to serve the CSP directive to the browser.

<br />

It's worth noting if you don't know already: [nonce](https://content-security-policy.com/nonce/) takes less performance, but changes the page on each request. [hashing](https://content-security-policy.com/hash/) requires more performance, but only changes when the components themselves change.

There's virtually no advantage to using `headers` over `meta-tags` and vice-versa.

### "Oh no, my Assets Aren't Loading!"
If you find a type of resource that isn't being handled properly, please PR or open an issue.

Naturally, some assets don't fit within our CSP-formatting needs. Assets such as Google Fonts will import a `.woff` that changes URL each request, so you would manually need to add `https://fonts.gstatic.com` to `font-src`.

There are two ways you can manually add assets. Firstly, all `<link>` elements are added, so you can add your assets to the `<head>` as a `preload`, `prefetch`, `prerender`, etc. Second, you can manually add a `<meta http-equiv="Content-Security-Policy" content="...">` to your `<head>` and it will get picked up automatically (works with `meta-tags` *and* `headers`).

As well, if you're using something like web-components, or you really like using the `style="..."` attribute, you can always add `"unsafe-inline"`, or any other [valid value](https://content-security-policy.com/#source_list).
