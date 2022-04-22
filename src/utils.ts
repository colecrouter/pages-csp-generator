import { CSPInlineHash } from "./csp";

export const absoluteURLRegex = /^(?:[a-z]+:)?\/\//i;
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

export const addHeader = (headers: Map<string, string[]>, key: string, value: string) => {
    if (value === "'none'") { headers.set(key, ["'none'"]); return; }
    if (!headers.has(key)) {
        headers.set(key, ["'self'"]);
    }
    if (value === "'self'") { return; }

    headers.get(key)!.push(value);
};

export const parseCSP = (headers: Map<string, string[]>, csp: string) => {
    const cspList = csp.split(";");
    for (const cspItem of cspList) {
        const [key, ...values] = cspItem.trim().split(" ");
        if (key && values) {
            for (const value of values) {
                addHeader(headers, key, value);
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