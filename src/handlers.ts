import { CSPOptions } from "./index";
import { scanCSS, scanCSSFile } from "./readers/css-scanner";
import { scanManifestFile } from "./readers/manifest-scanner";
import { AddHeader, CSPHeaders, HeadersToString, ParseCSP, RandomNonce, SHAHash, URLToHeader } from "./utils";

export class InsertMetaTagHandler {
    readonly options: CSPOptions;
    readonly headers: CSPHeaders;

    constructor(options: CSPOptions, headers: CSPHeaders) {
        this.options = options;
        this.headers = headers;
    }

    element(element: Element) {
        // Create new meta tag with CSP headers right before </head>
        element.prepend(`<meta http-equiv="Content-Security-Policy" content="${HeadersToString(this.options, this.headers)}">`, { html: true });
    }
}

export class ExistingMetaHandler {
    readonly options: CSPOptions;
    readonly request: Request;
    readonly headers: CSPHeaders;

    constructor(options: CSPOptions, request: Request, headers: CSPHeaders) {
        this.options = options;
        this.request = request;
        this.headers = headers;
    }

    element(element: Element) {
        if (element.tagName !== "meta") return; { }
        if (element.getAttribute("http-equiv") !== "Content-Security-Policy") { return; }

        // Parse existing CSP headers from meta tag
        ParseCSP(this.options, this.headers, element.getAttribute("content") || "");

        // Delete the meta tag
        element.remove();
    }
}

class InlineScriptHandler {
    readonly options: CSPOptions;
    readonly request: Request;
    readonly headers: CSPHeaders;
    readonly tagName: string;
    buffer = "";

    constructor(options: CSPOptions, request: Request, headers: CSPHeaders, tagName: string) {
        this.options = options;
        this.request = request;
        this.headers = headers;
        this.tagName = tagName;
    }

    // Scan text elements for urls
    async text(text: Text) {
        // If we're using 'strict-dynamic' on a script, skip because it'll be handled in the element() handler
        if (this.tagName === 'script' && this.headers.get("script-src")?.has("'strict-dynamic'")) { return; }

        // Accumulate buffer
        this.buffer += text.text;
        if (!text.lastInTextNode) { return; }

        // Find URLs
        const url = new URL(this.request.url);
        if (this.tagName === "style") { await scanCSS(this.options, this.headers, url, this.buffer); }
        if (this.tagName == "style" && this.headers.get("style-src")?.has("'unsafe-inline'")) { return; }; // Inline style attribute somewhere in page, don't add nonce
        if (this.options.InlineMethod === "nonce") { return; } // We want element() to handle nonce generation

        // Calculate hash
        let ident: string;
        let formattedIdent: string;
        switch (this.options.InlineMethod) {
            case "sha256":
            case "sha384":
            case "sha512":
                ident = await SHAHash(this.options, this.buffer); // Wait for the handler to have parsed the text
                formattedIdent = `'${this.options.InlineMethod}-${ident}'`; // Format the hash for CSP
                break;
        }

        // Add CSP header
        if (this.tagName === "script") { AddHeader(this.options, this.headers, "script-src", formattedIdent); }
        else if (this.tagName === "style") { AddHeader(this.options, this.headers, "style-src", formattedIdent); }

        this.buffer = ""; // Empty buffer
    }

    // Add nonce to inline script elements
    async element(element: Element) {
        if (this.tagName == "style" && this.headers.get("style-src")?.has("'unsafe-inline'")) { return; }; // Inline style attribute somewhere in page, don't add nonce

        // If there is an src or href attribute, it's not inline, we'll let SrcHrefHandler handle it
        // BUT, if the 'script-src' directive has 'strict-dynamic', then do it anyway (on scripts only),
        // cuz we need that to run inline scripts.

        // If not inline (has src attribute) and we're not using 'strict-dynamic', OR it has href (presumably a style, or something else 'strict-dynamic' doesn't affect), then skip
        if ((element.getAttribute('src') && !(this.headers.get("script-src")?.has("'strict-dynamic'"))) || element.getAttribute('href')) { return; }

        // If we're using 'strict-dynamic' on a script, OR it's anything element and we're using nonces, then add a nonce
        if ((element.tagName === 'script' && this.headers.get("script-src")?.has("'strict-dynamic'")) || this.options.InlineMethod === "nonce") {
            // Create an identifier corresponding to our selected method: nonce or hash
            let ident: string;
            let formattedIdent: string;
            ident = RandomNonce();
            element.setAttribute("nonce", ident); // We need to set the nonce attribute on the element
            formattedIdent = `'nonce-${ident}'`; // Format the nonce for CSP

            // Add CSP header
            if (this.tagName === "script") { AddHeader(this.options, this.headers, "script-src", formattedIdent); }
            else if (this.tagName === "style") { AddHeader(this.options, this.headers, "style-src", formattedIdent); }

            return;
        }

        // Otherwise, don't do anything, we'll deal with it in the text() handler
    }
};

export class CSSHandler extends InlineScriptHandler {
    constructor(options: CSPOptions, request: Request, headers: CSPHeaders) {
        super(options, request, headers, "style");
    }
}

export class JSHandler extends InlineScriptHandler {
    constructor(options: CSPOptions, request: Request, headers: CSPHeaders) {
        super(options, request, headers, "script");
    }
}

export class SrcHrefHandler {
    readonly options: CSPOptions;
    readonly headers: CSPHeaders;
    readonly request: Request;

    constructor(options: CSPOptions, request: Request, headers: CSPHeaders) {
        this.options = options;
        this.request = request;
        this.headers = headers;
    }

    async element(element: Element) {
        if (!element.getAttribute("src") && !element.getAttribute("href")) { return; }
        const value = element.getAttribute("src") || element.getAttribute("href")!;

        // Check for base64 and blobs
        if (value.startsWith("data:") && element.tagName === "img") {
            AddHeader(this.options, this.headers, 'img-src', 'data:');
            return;
        } else if (value.startsWith("blob:")) {
            if (element.tagName === "img") {
                AddHeader(this.options, this.headers, 'img-src', 'blob:');
            } else if (element.tagName === "script") {
                AddHeader(this.options, this.headers, 'script-src', 'blob:');
            }
            return;
        }

        // If 'strict-dynamic' is in the script-src directive and we're using nonces, we'll add a nonce
        if (element.tagName === 'script' && this.headers.get("script-src")?.has("'strict-dynamic'")) {
            if (this.options.InlineMethod === "nonce") {
                const ident = RandomNonce();
                element.setAttribute("nonce", ident);
                const formattedIdent = `'nonce-${ident}'`;
                AddHeader(this.options, this.headers, 'script-src', formattedIdent);
            } else {
                return;
            }
        }

        // URL to headers
        let url: URL;

        try { url = new URL(value, this.request.url); } catch (e) { return; }
        url.hash = ''; // Remove hash
        url.search = ''; // Remove search
        switch (element.tagName) {
            case 'script':
                await URLToHeader(this.options, this.headers, url);
                break;
            case 'link':
                switch (element.getAttribute("rel") || "") {
                    case 'stylesheet':
                        await scanCSSFile(this.options, this.headers, url);
                        await URLToHeader(this.options, this.headers, url, 'style-src');
                        break;
                    case 'apple-touch-icon':
                    case 'icon':
                        await URLToHeader(this.options, this.headers, url, 'img-src');
                        break;
                    case 'manifest':
                        await scanManifestFile(this.options, this.headers, url);
                        await URLToHeader(this.options, this.headers, url, 'manifest-src');
                        break;
                    case 'prerender':
                    case 'prefetch':
                        await URLToHeader(this.options, this.headers, url, 'prefetch-src');
                    case 'preconnect':
                    case 'preload':
                        switch (element.getAttribute("as")) {
                            case 'script':
                                await URLToHeader(this.options, this.headers, url, 'script-src');
                                break;
                            case 'style':
                                await scanCSSFile(this.options, this.headers, url);
                                await URLToHeader(this.options, this.headers, url, 'style-src');
                                break;
                            case 'font':
                                await URLToHeader(this.options, this.headers, url, 'font-src');
                                break;
                            case 'image':
                                await URLToHeader(this.options, this.headers, url, 'img-src');
                                break;
                            case 'audio':
                            case 'video':
                                await URLToHeader(this.options, this.headers, url, 'media-src');
                                break;
                            case 'object':
                                await URLToHeader(this.options, this.headers, url, 'object-src');
                                break;
                            case 'worker':
                                await URLToHeader(this.options, this.headers, url, 'worker-src');
                                break;
                            case 'document':
                                await URLToHeader(this.options, this.headers, url, 'child-src');
                                break;
                            case 'fetch':
                                await URLToHeader(this.options, this.headers, url, 'connect-src');
                                break;
                            case 'manifest':
                                await scanManifestFile(this.options, this.headers, url);
                                await URLToHeader(this.options, this.headers, url, 'manifest-src');
                                break;
                        }
                        break;
                }
                break;
            case 'img':
                await URLToHeader(this.options, this.headers, url, 'img-src');
                break;
            case 'audio':
            case 'video':
                await URLToHeader(this.options, this.headers, url, 'media-src');
                break;
            case 'iframe':
            case 'frame':
                await URLToHeader(this.options, this.headers, url, 'child-src');
                break;
            case 'object':
            case 'embed':
            case 'applet':
                await URLToHeader(this.options, this.headers, url, 'object-src');
                break;
            case 'form':
                await URLToHeader(this.options, this.headers, url, 'form-action');
                break;
            // case 'a':
            //     await urlToHeader(this.options, this.headers, url, 'navigate-to');
            //     break;

        }
    }
}

export class AnchorHandler {
    readonly options: CSPOptions;
    readonly request: Request;
    readonly headers: CSPHeaders;

    constructor(options: CSPOptions, request: Request, headers: CSPHeaders) {
        this.options = options;
        this.request = request;
        this.headers = headers;
    }

    async element(element: Element) {
        const ping = element.getAttribute("ping");
        if (!ping) { return; }

        await URLToHeader(this.options, this.headers, new URL(ping, this.request.url), "connect-src");
    }
}

export class InlineStyleFinder {
    readonly options: CSPOptions;
    readonly headers: CSPHeaders;

    constructor(options: CSPOptions, headers: CSPHeaders) {
        this.options = options;
        this.headers = headers;
    }

    async element(element: Element) {
        if (element.hasAttribute("style")) { // Check for any inline style attributes, as we can't handle those via CSP
            AddHeader(this.options, this.headers, 'style-src', "'unsafe-inline'");
        }
    }
}