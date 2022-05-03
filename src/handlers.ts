import { CSPInlineMethod, CSPOptions } from "./csp";
import { scanCSS, scanCSSFile } from "./readers/css-scanner";
import { scanJS, scanJSFile } from "./readers/js-scanner";
import { absoluteURLRegex as AbsoluteURLRegex, addHeader, headersToString, parseCSP, randomNonce, SHAHash, urlToHeader } from "./utils";

export class InsertMetaTagHandler {
    readonly options: CSPOptions;
    readonly headers: Map<string, string[]>;

    constructor(options: CSPOptions, headers: Map<string, string[]>) {
        this.options = options;
        this.headers = headers;
    }

    element(element: Element) {
        // Create new meta tag with CSP headers right before </head>
        element.prepend(`<meta http-equiv="Content-Security-Policy" content="${headersToString(this.options, this.headers)}">`, { html: true });
    }
}

export class ExistingMetaHandler {
    readonly options: CSPOptions;
    readonly request: Request;
    readonly headers: Map<string, string[]>;

    constructor(options: CSPOptions, request: Request, headers: Map<string, string[]>) {
        this.options = options;
        this.request = request;
        this.headers = headers;
    }

    element(element: Element) {
        if (element.tagName !== "meta") return; { }
        if (element.getAttribute("http-equiv") !== "Content-Security-Policy") { return; }

        // Parse existing CSP headers from meta tag
        parseCSP(this.options, this.headers, element.getAttribute("content") || "");

        // Delete the meta tag
        element.remove();
    }
}

class InlineScriptHandler {
    readonly options: CSPOptions;
    readonly request: Request;
    readonly headers: Map<string, string[]>;
    readonly tagName: string;
    buffer = "";

    constructor(options: CSPOptions, request: Request, headers: Map<string, string[]>, tagName: string) {
        this.options = options;
        this.request = request;
        this.headers = headers;
        this.tagName = tagName;
    }

    // Scan text elements for urls
    async text(text: Text) {
        // Accumulate buffer
        this.buffer += text.text;
        if (!text.lastInTextNode) { return; }

        // Recurse and find URLs
        const url = new URL(this.request.url);
        if (this.tagName === "script") { await scanJS(this.options, this.headers, url, this.buffer); }
        else if (this.tagName === "style") { await scanCSS(this.options, this.headers, url, this.buffer); }

        if (this.tagName == "style" && this.headers.get("style-src")?.includes("'unsafe-inline'")) { return; }; // Inline style attribute somewhere in page, don't add nonce
        if (this.options.InlineMethod === "nonce") { return; } // We want element() to handle nonce generation

        // Calculate hash
        let ident: string;
        let formattedIdent: string;
        switch (this.options.InlineMethod) {
            case "sha256":
            case "sha384":
            case "sha512":
                ident = await SHAHash(this.options, this.buffer, this.options.InlineMethod); // Wait for the handler to have parsed the text
                formattedIdent = `'${this.options.InlineMethod}-${ident}'`; // Format the hash for CSP
                break;
        }

        // Add CSP header
        if (this.tagName === "script") { addHeader(this.options, this.headers, "script-src", formattedIdent); }
        else if (this.tagName === "style") { addHeader(this.options, this.headers, "style-src", formattedIdent); }

        this.buffer = ""; // Empty buffer
    }

    // Add nonce to inline script elements
    async element(element: Element) {
        if (this.tagName == "style" && this.headers.get("style-src")?.includes("'unsafe-inline'")) { return; }; // Inline style attribute somewhere in page, don't add nonce

        // If there is an src or href attribute, it's not inline
        // We'll let SrcHrefHandler handle it
        // BUT, if the 'script-src' directive has 'strict-dynamic', then do it anyway, cuz we need that to run inline scripts
        // If the metod isn't 'nonce', we'll have to hash it here instead of in text() (if there's 'strict-dynamic')
        if ((element.getAttribute("src") || element.getAttribute("href")) && !(this.tagName == "script" && this.headers.get("script-src")?.includes("'strict-dynamic'"))) { return; }

        // We want element() to handle nonce generation, UNLESS we have a 'strict-dynamic' directive, in which case, we'll do it here
        if (this.tagName == "script" && element.getAttribute("src") && this.options.InlineMethod !== "nonce") {
            // Get contents of src
            const url = new URL(element.getAttribute("src")!, this.request.url);
            const text = await fetch(url.toString());

            // Calculate hash
            let ident: string;
            let formattedIdent: string;
            switch (this.options.InlineMethod) {
                case "sha256":
                case "sha384":
                case "sha512":
                    ident = await SHAHash(this.options, await text.text(), this.options.InlineMethod); // Wait for the handler to have parsed the text
                    formattedIdent = `'${this.options.InlineMethod}-${ident}'`; // Format the hash for CSP
                    break;
            }

            // Add CSP header
            await urlToHeader(this.options, this.headers, url);
            return;
        }

        // Create an identifier corresponding to our selected method: nonce or hash
        let ident: string;
        let formattedIdent: string;
        ident = randomNonce();
        element.setAttribute("nonce", ident); // We need to set the nonce attribute on the element
        formattedIdent = `'nonce-${ident}'`; // Format the nonce for CSP

        // Add CSP header
        if (this.tagName === "script") { addHeader(this.options, this.headers, "script-src", formattedIdent); }
        else if (this.tagName === "style") { addHeader(this.options, this.headers, "style-src", formattedIdent); }
    }
};

export class CSSHandler extends InlineScriptHandler {
    constructor(options: CSPOptions, request: Request, headers: Map<string, string[]>) {
        super(options, request, headers, "style");
    }
}

export class JSHandler extends InlineScriptHandler {
    constructor(options: CSPOptions, request: Request, headers: Map<string, string[]>) {
        super(options, request, headers, "script");
    }
}

export class SrcHrefHandler {
    readonly options: CSPOptions;
    readonly headers: Map<string, string[]>;
    readonly request: Request;

    constructor(options: CSPOptions, request: Request, headers: Map<string, string[]>) {
        this.options = options;
        this.request = request;
        this.headers = headers;
    }

    async element(element: Element) {
        if (!element.getAttribute("src") && !element.getAttribute("href")) { return; }

        // Check for base64 and blobs
        const value = element.getAttribute("src") || element.getAttribute("href")!;
        if (value.startsWith("data:") && element.tagName === "img") {
            addHeader(this.options, this.headers, 'img-src', 'data:');
            return;
        } else if (value.startsWith("blob:")) {
            if (element.tagName === "img") {
                addHeader(this.options, this.headers, 'img-src', 'blob:');
            } else if (element.tagName === "script") {
                addHeader(this.options, this.headers, 'script-src', 'blob:');
            }
            return;
        }

        // URL to headers
        let url: URL;

        try { url = new URL(value, this.request.url); } catch (e) { return; }
        url.hash = ''; // Remove hash
        url.search = ''; // Remove search
        switch (element.tagName) {
            case 'script':
                await scanJSFile(this.options, this.headers, url);
                if (AbsoluteURLRegex.test(url.toString())) {
                    await urlToHeader(this.options, this.headers, url);
                }
                break;
            case 'link':
                switch (element.getAttribute("rel") || "") {
                    case 'stylesheet':
                        await scanCSSFile(this.options, this.headers, url);
                        await urlToHeader(this.options, this.headers, url, 'style-src');
                        break;
                    case 'apple-touch-icon':
                    case 'icon':
                        await urlToHeader(this.options, this.headers, url, 'img-src');
                        break;
                    case 'manifest':
                        await scanJSFile(this.options, this.headers, url);
                        await urlToHeader(this.options, this.headers, url, 'manifest-src');
                        break;
                    case 'prerender':
                    case 'prefetch':
                        await urlToHeader(this.options, this.headers, url, 'prefetch-src');
                    case 'preconnect':
                    case 'preload':
                        switch (element.getAttribute("as")) {
                            case 'script':
                                await scanJSFile(this.options, this.headers, url);
                                await urlToHeader(this.options, this.headers, url, 'script-src');
                                break;
                            case 'style':
                                await scanCSSFile(this.options, this.headers, url);
                                await urlToHeader(this.options, this.headers, url, 'style-src');
                                break;
                            case 'font':
                                await urlToHeader(this.options, this.headers, url, 'font-src');
                                break;
                            case 'image':
                                await urlToHeader(this.options, this.headers, url, 'img-src');
                                break;
                            case 'audio':
                            case 'video':
                                await urlToHeader(this.options, this.headers, url, 'media-src');
                                break;
                            case 'object':
                                await urlToHeader(this.options, this.headers, url, 'object-src');
                                break;
                            case 'worker':
                                await urlToHeader(this.options, this.headers, url, 'worker-src');
                                break;
                            case 'document':
                                await urlToHeader(this.options, this.headers, url, 'child-src');
                                break;
                            case 'fetch':
                                await urlToHeader(this.options, this.headers, url, 'connect-src');
                                break;
                            case 'manifest':
                                await scanJSFile(this.options, this.headers, url);
                                await urlToHeader(this.options, this.headers, url, 'manifest-src');
                                break;
                        }
                        break;
                }
                break;
            case "img":
                await urlToHeader(this.options, this.headers, url, 'img-src');
        }
    }
}

export class AnchorHandler {
    readonly options: CSPOptions;
    readonly request: Request;
    readonly headers: Map<string, string[]>;

    constructor(options: CSPOptions, request: Request, headers: Map<string, string[]>) {
        this.options = options;
        this.request = request;
        this.headers = headers;
    }

    async element(element: Element) {
        const ping = element.getAttribute("ping");
        if (!ping) { return; }

        await urlToHeader(this.options, this.headers, new URL(ping, this.request.url), "connect-src");
    }
}

export class InlineStyleFinder {
    readonly options: CSPOptions;
    readonly headers: Map<string, string[]>;

    constructor(options: CSPOptions, headers: Map<string, string[]>) {
        this.options = options;
        this.headers = headers;
    }

    async element(element: Element) {
        if (element.hasAttribute("style")) { // Check for any inline style attributes, as we can't handle those via CSP
            addHeader(this.options, this.headers, 'style-src', "'unsafe-inline'");
        }
    }
}