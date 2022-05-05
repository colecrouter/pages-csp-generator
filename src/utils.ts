import { CSPOptions, localhost } from "./csp";

export const absoluteURLRegex = /["'`]?((?:http|https):\/\/[a-z0-9]+(?:\.[a-z]*)?(?::[0-9]+)?[\/a-z0-9.\-@]*)[\?#]?.*?["'`]?/gi;
export const base64Regex = /['"`]?(data:(?<mime>[\w\/\-\.]+);(?<encoding>\w+),(?<data>.*))['"`]?/gi;

const CSPDirectives: CSPDirective[] = [
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

export type CSPHeaders = Map<CSPDirective, Set<string>>;

const fetchDirectiveCache = new Map<string, CSPDirective | null>();

export const RandomNonce = (): string => {
    for (var a = '', b = 36; a.length < 16;) a += (Math.random() * b | 0).toString(b);
    return a;
};

export const SHAHash = async (options: CSPOptions, str: string): Promise<string> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);

    // Translate method to appropriate hash function
    let translatedMethod;
    switch (options.InlineMethod!) {
        case "sha256":
            translatedMethod = "SHA-256";
            break;
        case "sha384":
            translatedMethod = "SHA-384";
            break;
        case "sha512":
            translatedMethod = "SHA-512";
            break;
        default:
            throw new Error(`unknown hash method: ${options.InlineMethod}`);
    }

    const hash = await crypto.subtle.digest(translatedMethod, data);
    return btoa(String.fromCharCode(...new Uint8Array(hash)));;
};

export const AddHeader = (options: CSPOptions, headers: CSPHeaders, key: CSPDirective, value: URL | string) => {
    if (value === "'none'") { return; }
    if (!headers.has(key)) { headers.set(key, new Set()); }// Initialize if not already
    const values = headers.get(key)!;

    // Add value
    if (typeof value === 'string') {
        values.add(value);
        return;
    }

    // Case for 'data:' and 'blob:'
    if (value.origin === null) {
        values.add(value.href);
        return;
    }

    // If URL, check for existing values that conflict
    value.hash = '';
    value.search = '';
    for (const [existing, _] of values.entries()) { // I'm not sure why, this sets 'existing' a string of an index (number), instead of the value????
        if (existing.startsWith("'") && existing.endsWith("'")) { continue; } // If not url, skip

        const existingValue = new URL(existing);
        if (existingValue.origin !== value.origin) { continue; } // Not on same domain, will not conflict, skip
        if (existingValue.pathname === '/') { return; } // Already have domain wide access, skip
        if (value.pathname === '/') { values.delete(existing); } // Remove the more specific directive, it will be redundant

    }

    // Add value, use 'self' if set in options
    values.add(options.UseSelf && value.origin === localhost ? "'self'" : value.toString());
};

export const ParseCSP = (options: CSPOptions, headers: CSPHeaders, csp: string) => {
    const cspList = csp.split(";");
    for (const cspItem of cspList) {
        const [key, ...values] = cspItem.trim().split(" ");
        if (key && values) {
            for (const value of values) {
                if (value.startsWith("'") && value.endsWith("'")) {
                    AddHeader(options, headers, key as CSPDirective, value);
                    continue;
                }

                // Try to parse as URL
                try {
                    const url = new URL(value);
                    AddHeader(options, headers, key as CSPDirective, url);
                } catch (e) { }
            }
        }
    }
};

export const HeadersToString = (options: CSPOptions, headers: CSPHeaders): string => {
    // Make sure default is set to 'none'
    if (!headers.has("default-src")) { headers.set("default-src", new Set(["'none'"])); }

    // Build CSP header
    let csp = "";
    for (const directive of CSPDirectives) {
        const values = headers.get(directive);
        if (values && values.size > 0) {
            csp += `${directive} ${[...headers.get(directive)!].join(" ")}; `;
        }
    }

    return csp;
};

export const URLToHeader = async (options: CSPOptions, headers: CSPHeaders, url: URL, directive?: CSPDirective) => {

    // Get directive
    directive = directive || getDirectiveFromExtension(options, url) || await getDirectiveFromFetch(options, url);
    if (!directive) { return; }


    // If pathname has ${ in it, we'll assume it's a template and return the hostname.
    if (url.pathname.includes("$%7B")) { return AddHeader(options, headers, directive, url); }

    // Absolute URL
    url.hash = "";
    url.search = "";
    if (url.origin !== localhost) { return AddHeader(options, headers, directive, url); }

    // Relative URL
    return AddHeader(options, headers, directive, options.UseSelf ? "'self'" : url);
};

// Not currently used

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
    const doCache = url.origin === localhost;

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