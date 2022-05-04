import { CSPInlineHash, CSPOptions, localhost } from "./csp";

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

const fetchDirectiveCache = new Map<string, CSPDirective | null>();

export const randomNonce = (): string => {
    for (var a = '', b = 36; a.length < 16;) a += (Math.random() * b | 0).toString(b);
    return a;
};

export const SHAHash = async (options: CSPOptions, str: string, method: CSPInlineHash): Promise<string> => {
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

export const addHeader = (options: CSPOptions, headers: Map<string, string[]>, key: CSPDirective, value: string) => {
    if (value === "'none'") { return; } // None will get added at the end
    if (!headers?.has(key)) { headers.set(key, ["'self'"]); }// Initialize if not already
    if (headers.get(key)!.includes(value)) { return; } // Don't add if already there
    if (value === "'unsafe-inline") { return; } // If unsafe-inline, remove all nonces

    // Check for existing values that conflict
    const values = headers.get(key);
    for (const existing in values) { // I'm not sure why, this sets 'existing' a string of an index (number), instead of the value????
        // Check for existing values that are less specific than the new value
        if (value.startsWith(values[existing as any])) {
            return;
        }

        // Check for existing values that are more specific than the new value
        // I don't know if this will happen in this implementation yet, but maybe in the future
        if (values[existing as any].startsWith(value)) {
            values.splice(existing as any, 1);
        }
    }


    headers.get(key)!.push(value);
};

export const parseCSP = (options: CSPOptions, headers: Map<string, string[]>, csp: string) => {
    const cspList = csp.split(";");
    for (const cspItem of cspList) {
        const [key, ...values] = cspItem.trim().split(" ");
        if (key && values) {
            for (const value of values) {
                addHeader(options, headers, key as CSPDirective, value);
            }
        }
    }
};

export const headersToString = (options: CSPOptions, headers: Map<string, string[]>): string => {
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

export const urlToHeader = async (options: CSPOptions, headers: Map<string, string[]>, url: URL, directive?: CSPDirective) => {

    // Get directive
    directive = directive || getDirectiveFromExtension(options, url) || await getDirectiveFromFetch(options, url);
    if (!directive) { return; }


    // If pathname has ${ in it, we'll assume it's a template and return the hostname.
    if (url.pathname.includes("$%7B")) { return addHeader(options, headers, directive, url.hostname); }

    // Absolute URL
    url.hash = "";
    url.search = "";
    if (url.origin !== localhost) { return addHeader(options, headers, directive, url.toString()); }

    // Relative URL
    return addHeader(options, headers, directive, "'self'");
};

const getDirectiveFromExtension = (options: CSPOptions, url: URL): CSPDirective | undefined => {
    switch (url.pathname.split(".").pop()) {
        case 'svg':
        case 'jpeg':
        case 'jpg':
        case 'png':
        case 'gif':
        case 'bmp':
        case 'tiff':
        case 'webp':
        case 'avif':
        case 'ico':
            return "img-src";
        case 'woff':
        case 'woff2':
        case 'eot':
        case 'ttf':
        case 'otf':
            return "font-src";
        case 'js':
            return "script-src";
        case 'css':
            return "style-src";
        case 'json':
            return "connect-src";
        default:
            return undefined;
    }
};

const getDirectiveFromFetch = async (options: CSPOptions, url: URL): Promise<CSPDirective | undefined> => {
    const doCache = options.CacheMethod === 'all' || (url.origin === localhost && options.CacheMethod === 'localhost');

    // Check cache
    if (doCache && fetchDirectiveCache.has(url.toString())) { return fetchDirectiveCache.get(url.toString()) || undefined; }

    // Fetch rquest, determine MIME type
    const res = await fetch(url.toString());
    const mime = res.headers.get("Content-Type");
    if (res.status !== 200 || !mime) { fetchDirectiveCache.set(url.toString(), null); return; } // Cache, but set as nothing

    const category = mime.split("/").shift();
    let directive: CSPDirective;
    switch (category) {
        case 'application':
        case 'text': // ???
            directive = 'script-src';
            break;
        case 'audio':
        case 'video':
            directive = 'media-src';
            break;
        case 'font':
            directive = 'font-src';
            break;
        case 'image':
            directive = 'img-src';
            break;
        case 'message':
        case 'model': // ???
        case 'multipart': // ???
            directive = 'connect-src';
            break;
        default:
            return undefined;
    }

    // Cache
    if (doCache) { fetchDirectiveCache.set(url.toString(), directive); };

    return directive;
};