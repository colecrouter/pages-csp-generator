import { CSPInlineMethod } from "./csp";
import { scanCSS, scanCSSFile } from "./readers/css-scanner";
import { scanJS, scanJSFile } from "./readers/js-scanner";
import { absoluteURLRegex as AbsoluteURLRegex, addHeader, headersToString, parseCSP, randomNonce, SHAHash } from "./utils";

export class InsertMetaTagHandler {
    headers: Map<string, string[]>;

    constructor(headers: Map<string, string[]>) {
        this.headers = headers;
    }

    element(element: Element) {
        // Create new meta tag with CSP headers right before </head>
        element.prepend(`<meta http-equiv="Content-Security-Policy" content="${headersToString(this.headers)}">`, { html: true });
    }
}

export class ExistingMetaHandler {
    request: Request;
    headers: Map<string, string[]>;

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
    request: Request;
    headers: Map<string, string[]>;
    method: CSPInlineMethod;
    tagName: string;
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
        if (this.tagName === "script") { scanJS(this.headers, this.request.url, this.buffer); }
        else if (this.tagName === "style") { scanCSS(this.headers, this.request.url, this.buffer); }

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
            console.log(url);

            // Calculate hash
            let ident: string;
            let formattedIdent: string;
            switch (this.method) {
                case "sha256":
                case "sha384":
                case "sha512":
                    ident = await SHAHash(await text.text(), this.method); // Wait for the handler to have parsed the text
                    console.log(element.getAttribute("src"), ident);
                    formattedIdent = `'${this.method}-${ident}'`; // Format the hash for CSP
                    break;
            }

            // Add CSP header
            addHeader(this.headers, "script-src", formattedIdent);
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
    headers: Map<string, string[]>;
    request: Request;

    constructor(request: Request, headers: Map<string, string[]>) {
        this.request = request;
        this.headers = headers;
    }

    element(element: Element) {
        if (!element.getAttribute("src") && !element.getAttribute("href")) { return; }

        // URL to headers
        let url;
        let rel;
        switch (element.tagName) {
            case "script":
                url = element.getAttribute("src")!.split('?')[0];
                url = new URL(url, this.request.url).toString();
                scanJSFile(this.headers, url);
                if (AbsoluteURLRegex.test(url)) {
                    addHeader(this.headers, "script-src", url);
                }
                break;
            case "link":
                url = element.getAttribute("href")!.split('?')[0];
                url = new URL(url, this.request.url).toString();
                rel = element.getAttribute("rel")!;
                // if (!AbsoluteURLRegex.test(url)) { return; }

                switch (rel) {
                    case "stylesheet":
                        scanCSSFile(this.headers, url);
                        addHeader(this.headers, "style-src", url);
                        break;
                    case "apple-touch-icon":
                    case "icon":
                        addHeader(this.headers, "img-src", url);
                        break;
                    case "prerender":
                    case "prefetch":
                        addHeader(this.headers, "prefetch-src", url);
                    case "preconnect":
                    case "preload":
                        switch (element.getAttribute("as")) {
                            case "script":
                                scanJSFile(this.headers, url);
                                addHeader(this.headers, "script-src", url);
                                break;
                            case "style":
                                scanCSSFile(this.headers, url);
                                addHeader(this.headers, "style-src", url);
                                break;
                            case "font":
                                addHeader(this.headers, "font-src", url);
                                break;
                            case "image":
                                addHeader(this.headers, "img-src", url);
                                break;
                            case "audio":
                            case "video":
                                addHeader(this.headers, "media-src", url);
                                break;
                            case "object":
                                addHeader(this.headers, "object-src", url);
                                break;
                            case "worker":
                            case "document":
                                addHeader(this.headers, "child-src", url);
                                break;
                            case "fetch":
                                addHeader(this.headers, "connect-src", url);
                                break;
                            case "manifest":
                                addHeader(this.headers, "manifest-src", url);
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
    headers: Map<string, string[]>;

    constructor(headers: Map<string, string[]>) {
        this.headers = headers;
    }

    element(element: Element) {
        const ping = element.getAttribute("ping");
        if (ping && AbsoluteURLRegex.test(ping)) { // If relative URL, skip
            addHeader(this.headers, "connect-src", ping);
        }
    }
}

export class InlineStyleFinder {
    headers: Map<string, string[]>;

    constructor(headers: Map<string, string[]>) {
        this.headers = headers;
    }

    element(element: Element) {
        if (element.hasAttribute("style")) { // Check for any inline style attributes, as we can't handle those via CSP
            addHeader(this.headers, "style-src", "'unsafe-inline'"); // This will stop nonce/hash generation
        }
    }
}