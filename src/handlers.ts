import { CSPInlineMethod } from "./csp";
import { scanCSS, scanCSSFile } from "./readers/css-scanner";
import { scanJS, scanJSFile } from "./readers/js-scanner";
import { absoluteURLRegex as AbsoluteURLRegex, addHeader, headersToString, parseCSP, randomNonce, SHAHash, urlToHeader } from "./utils";

export class InsertMetaTagHandler {
    readonly headers: Map<string, string[]>;

    constructor(headers: Map<string, string[]>) {
        this.headers = headers;
    }

    element(element: Element) {
        // Create new meta tag with CSP headers right before </head>
        element.prepend(`<meta http-equiv="Content-Security-Policy" content="${headersToString(this.headers)}">`, { html: true });
    }
}

export class ExistingMetaHandler {
    readonly request: Request;
    readonly headers: Map<string, string[]>;

    constructor(request: Request, headers: Map<string, string[]>) {
        this.request = request;
        this.headers = headers;
    }

    element(element: Element) {
        if (element.tagName !== "meta") return; { }
        if (element.getAttribute("http-equiv") !== "Content-Security-Policy") { return; }

        // Parse existing CSP headers from meta tag
        parseCSP(this.headers, element.getAttribute("content") || "");

        // Delete the meta tag
        element.remove();
    }
}

class InlineScriptHandler {
    readonly request: Request;
    readonly headers: Map<string, string[]>;
    readonly method: CSPInlineMethod;
    readonly tagName: string;
    buffer = "";

    constructor(request: Request, headers: Map<string, string[]>, method: CSPInlineMethod, tagName: string) {
        this.request = request;
        this.headers = headers;
        this.method = method;
        this.tagName = tagName;
    }

    // Scan text elements for urls
    async text(text: Text) {
        // Accumulate buffer
        this.buffer += text.text;
        if (!text.lastInTextNode) { return; }

        // Recurse and find URLs
        if (this.tagName === "script") { await scanJS(this.headers, this.request.url, this.buffer); }
        else if (this.tagName === "style") { await scanCSS(this.headers, this.request.url, this.buffer); }

        if (this.tagName == "style" && this.headers.get("style-src")?.includes("'unsafe-inline'")) { return; }; // Inline style attribute somewhere in page, don't add nonce
        if (this.method === "nonce") { return; } // We want element() to handle nonce generation

        // Calculate hash
        let ident: string;
        let formattedIdent: string;
        switch (this.method) {
            case "sha256":
            case "sha384":
            case "sha512":
                ident = await SHAHash(this.buffer, this.method); // Wait for the handler to have parsed the text
                formattedIdent = `'${this.method}-${ident}'`; // Format the hash for CSP
                break;
        }

        // Add CSP header
        if (this.tagName === "script") { addHeader(this.headers, "script-src", formattedIdent); }
        else if (this.tagName === "style") { addHeader(this.headers, "style-src", formattedIdent); }

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
        if (this.tagName == "script" && element.getAttribute("src") && this.method !== "nonce") {
            // Get contents of src
            const url = new URL(element.getAttribute("src")!, this.request.url).toString();
            const text = await fetch(url);

            // Calculate hash
            let ident: string;
            let formattedIdent: string;
            switch (this.method) {
                case "sha256":
                case "sha384":
                case "sha512":
                    ident = await SHAHash(await text.text(), this.method); // Wait for the handler to have parsed the text
                    formattedIdent = `'${this.method}-${ident}'`; // Format the hash for CSP
                    break;
            }

            // Add CSP header
            urlToHeader(this.headers, url.toString());
            return;
        }

        // Create an identifier corresponding to our selected method: nonce or hash
        let ident: string;
        let formattedIdent: string;
        ident = randomNonce();
        element.setAttribute("nonce", ident); // We need to set the nonce attribute on the element
        formattedIdent = `'nonce-${ident}'`; // Format the nonce for CSP

        // Add CSP header
        if (this.tagName === "script") { addHeader(this.headers, "script-src", formattedIdent); }
        else if (this.tagName === "style") { addHeader(this.headers, "style-src", formattedIdent); }
    }
};

export class CSSHandler extends InlineScriptHandler {
    constructor(request: Request, headers: Map<string, string[]>, method: CSPInlineMethod) {
        super(request, headers, method, "style");
    }
}

export class JSHandler extends InlineScriptHandler {
    constructor(request: Request, headers: Map<string, string[]>, method: CSPInlineMethod) {
        super(request, headers, method, "script");
    }
}

export class SrcHrefHandler {
    readonly headers: Map<string, string[]>;
    readonly request: Request;

    constructor(request: Request, headers: Map<string, string[]>) {
        this.request = request;
        this.headers = headers;
    }

    async element(element: Element) {
        if (!element.getAttribute("src") && !element.getAttribute("href")) { return; }

        // URL to headers
        let url = "";
        let rel = "";
        switch (element.tagName) {
            case "script":
                url = element.getAttribute("src")!.split('?')[0];
                url = new URL(url, this.request.url).toString();
                await scanJSFile(this.headers, url);
                if (AbsoluteURLRegex.test(url)) {
                    urlToHeader(this.headers, url);
                }
                break;
            case "link":
                url = element.getAttribute("href")!.split('?')[0];
                url = new URL(url, this.request.url).toString();
                rel = element.getAttribute("rel")!;
                // if (!AbsoluteURLRegex.test(url)) { return; }

                switch (rel) {
                    case "stylesheet":
                        await scanCSSFile(this.headers, url);
                        urlToHeader(this.headers, url, 'style-src');
                        break;
                    case "apple-touch-icon":
                    case "icon":
                        urlToHeader(this.headers, url, 'img-src');
                        break;
                    case "manifest":
                        await scanJSFile(this.headers, url);
                        urlToHeader(this.headers, url, 'manifest-src');
                        break;
                    case "prerender":
                    case "prefetch":
                        urlToHeader(this.headers, url, 'prefetch-src');
                    case "preconnect":
                    case "preload":
                        switch (element.getAttribute("as")) {
                            case "script":
                                await scanJSFile(this.headers, url);
                                urlToHeader(this.headers, url, 'script-src');
                                break;
                            case "style":
                                await scanCSSFile(this.headers, url);
                                urlToHeader(this.headers, url, 'style-src');
                                break;
                            case "font":
                                urlToHeader(this.headers, url, 'font-src');
                                break;
                            case "image":
                                urlToHeader(this.headers, url, 'img-src');
                                break;
                            case "audio":
                            case "video":
                                urlToHeader(this.headers, url, 'media-src');
                                break;
                            case "object":
                                urlToHeader(this.headers, url, 'object-src');
                                break;
                            case "worker":
                                urlToHeader(this.headers, url, 'worker-src');
                                break;
                            case "document":
                                urlToHeader(this.headers, url, 'child-src');
                                break;
                            case "fetch":
                                urlToHeader(this.headers, url, 'connect-src');
                                break;
                            case "manifest":
                                await scanJSFile(this.headers, url);
                                urlToHeader(this.headers, url, 'manifest-src');
                                break;
                        }
                        break;
                }
                break;
            case "img":
                url = element.getAttribute("src")!.split('?')[0];
                if (AbsoluteURLRegex.test(url)) {
                    addHeader(this.headers, "img-src", url);
                } else if (url.startsWith("data:")) {
                    addHeader(this.headers, "img-src", "data:");
                }
        }
    }
}

export class AnchorHandler {
    readonly headers: Map<string, string[]>;

    constructor(headers: Map<string, string[]>) {
        this.headers = headers;
    }

    element(element: Element) {
        const ping = element.getAttribute("ping");
        if (ping && AbsoluteURLRegex.test(ping)) { // If relative URL, skip
            urlToHeader(this.headers, ping, "connect-src");
        }
    }
}

export class InlineStyleFinder {
    readonly headers: Map<string, string[]>;

    constructor(headers: Map<string, string[]>) {
        this.headers = headers;
    }

    element(element: Element) {
        if (element.hasAttribute("style")) { // Check for any inline style attributes, as we can't handle those via CSP
            urlToHeader(this.headers, "'unsafe-inline'", "style-src"); // This will stop nonce/hash generation
        }
    }
}