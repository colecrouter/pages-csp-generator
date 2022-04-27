import { CSPInlineHash, localhost } from "./csp";

export const absoluteURLRegex = /["'`]?((?:http|https):\/\/[a-z0-9]+(?:\.[a-z]*)?(?::[0-9]+)?[\/a-z0-9.\-@]*)[\?#]?.*?["'`]?/gi;
export const base64Regex = /['"`]?(data:(?<mime>[\w\/\-\.]+);(?<encoding>\w+),(?<data>.*))['"`]?/gi;

const CSPDirectives: string[] = [
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "connect-src",
    "font-src",
    "object-src",
    "media-src",
    "frame-src",
    "sandbox",
    "report-uri",
    "child-src",
    "form-action", // TODO
    "frame-ancestors", // TODO
    "plugin-types", // TODO
    "base-uri", // TODO
    "report-to", // TODO
    "worker-src",
    "manifest-src",
    "prefetch-src",
    "navigate-to"
];

export type CSPDirective =
    "default-src" |
    "script-src" |
    "style-src" |
    "img-src" |
    "connect-src" |
    "font-src" |
    "object-src" |
    "media-src" |
    "frame-src" |
    "sandbox" |
    "report-uri" |
    "child-src" |
    "form-action" |
    "frame-ancestors" |
    "plugin-types" |
    "base-uri" |
    "report-to" |
    "worker-src" |
    "manifest-src" |
    "prefetch-src" |
    "navigate-to";

export const randomNonce = (): string => {
    for (var a = '', b = 36; a.length < 16;) a += (Math.random() * b | 0).toString(b);
    return a;
};

export const SHAHash = async (str: string, method: CSPInlineHash): Promise<string> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);

    // Translate method to appropriate hash function
    let translatedMethod;
    switch (method) {
        case "sha256":
            translatedMethod = "SHA-256";
            break;
        case "sha384":
            translatedMethod = "SHA-384";
            break;
        case "sha512":
            translatedMethod = "SHA-512";
            break;
    }

    const hash = await crypto.subtle.digest(translatedMethod, data);
    return btoa(String.fromCharCode(...new Uint8Array(hash)));;
};

export const addHeader = (headers: Map<string, string[]>, key: CSPDirective, value: string) => {
    if (value === "'none'") { return; } // None will get added at the end
    if (!headers.has(key)) { headers.set(key, ["'self'"]); }// Initialize if not already
    if (headers.get(key)!.includes(value)) { return; } // Don't add if already there
    if (value === "'unsafe-inline") { return; } // If unsafe-inline, remove all nonces
    headers.get(key)!.push(value);
};

export const parseCSP = (headers: Map<string, string[]>, csp: string) => {
    const cspList = csp.split(";");
    for (const cspItem of cspList) {
        const [key, ...values] = cspItem.trim().split(" ");
        if (key && values) {
            for (const value of values) {
                addHeader(headers, key as CSPDirective, value);
            }
        }
    }
};

export const headersToString = (headers: Map<string, string[]>): string => {
    // Build CSP header
    let csp = "";
    for (const directive of CSPDirectives) {
        if (headers.has(directive)) {
            csp += `${directive} ${headers.get(directive)!.join(" ")}; `;
        } else if (directive.endsWith("-src")) {
            csp += `${directive} 'none'; `;
        }
    }
    return csp;
};

export const urlToHeader = (headers: Map<string, string[]>, url: string, directive?: CSPDirective) => {
    // Remove surrounding quotes
    url = url.replace(/^[`'"]|[`'"]$/g, "");

    // Get directive
    directive = directive || getDirectiveFromExtension(url.split(".").pop() || "");

    // Parse as new URL so that we can extract certain parts of it.
    const parsed = new URL(url, localhost);

    // If pathname has ${ in it, we'll assume it's a template and return the hostname.
    if (parsed.pathname.includes("$%7B")) { return addHeader(headers, directive, parsed.hostname); }

    // Absolute URL
    const absoluteURL = url.match(absoluteURLRegex)?.[0];
    if (absoluteURL && parsed.origin !== localhost) { return addHeader(headers, directive, absoluteURL); }

    // Relative URL
    return addHeader(headers, directive, "'self'");
};

const getDirectiveFromExtension = (extension: string): CSPDirective => {
    switch (extension) {
        case "svg":
        case "jpeg":
        case "jpg":
        case "png":
        case "gif":
        case "bmp":
        case "tiff":
        case "webp":
        case "ico":
            return "img-src";
        case "woff":
        case "woff2":
        case "eot":
        case "ttf":
        case "otf":
            return "font-src";
        case "js":
            return "script-src";
        case "css":
            return "style-src";
        case "json":
            return "connect-src";
        default:
            return "style-src";
    }
};