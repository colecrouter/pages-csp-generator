import { localhost } from "../csp";
import { addHeader, CSPDirective } from "../utils";

const serviceWorkerRegex = /navigator\.serviceWorker\.register\('(.*)'\)/gi;
const absoluteURLRegex = /["'`]([a-z]+:\/\/.*\.[a-z]+[a-z0-9\/]*)[\?#]?.*["'`]/gi;
const relativeURLRegex = /["''](?!.*\/\/)(.*\.[a-z]+)["'']/gi;
const base64Regex = /['"`]?(data:(?<mime>[\w\/\-\.]+);(?<encoding>\w+),(?<data>.*))['"`]?/gi;

const cache = new Map<string, string[]>();

export const scanJSFile = async (headers: Map<string, string[]>, url: string): Promise<void> => {
    // Check cache
    if (cache.has(url)) {
        for (const value of cache.get(url)!) {
            addHeader(headers, value[0] as CSPDirective, value[1]);
        }
        return;
    }

    // Get file contents
    const response = await fetch(url);
    if (!response.ok) { return; }
    const text = await response.text();

    // Search for absolute URLs
    for (const match in text.matchAll(absoluteURLRegex)) {
        const filtered = filterURL(match);
        if (filtered) {
            addHeader(headers, "script-src", filtered);
        }
    }

    // Search for base64
    for (const match of text.matchAll(base64Regex)) {
        if (match.groups?.mime.startsWith("image/")) {
            addHeader(headers, "img-src", "data:");
        }
    }

    // Search for relative URLs
    for (const match in text.matchAll(relativeURLRegex)) {
        if (match.startsWith("data:")) { addHeader(headers, "img-src", "data:"); }
        else if (match.startsWith("glob:")) { addHeader(headers, "script-src", "data:"); }
        else { addHeader(headers, "script-src", "'self'"); addHeader(headers, "connect-src", url); }

        // Recurse
        await scanJSFile(headers, new URL(match, url).toString());
    }

    // Cache
    // cache.set(url, matches);
};

export const scanJS = async (headers: Map<string, string[]>, url: string, text: string): Promise<void> => {
    // Search for absolute URLs
    for (const match of text.matchAll(absoluteURLRegex)) {
        const filtered = filterURL(match[1]);
        if (filtered) {
            addHeader(headers, "script-src", filtered);
        }
    }

    // Search for base64
    for (const match of text.matchAll(base64Regex)) {
        if (match.groups?.mime.startsWith("image/")) {
            addHeader(headers, "img-src", "data:");
        }
    }

    // Search for relative URLs
    for (const match of text.matchAll(relativeURLRegex)) {
        if (match[1].startsWith("data:")) { addHeader(headers, "img-src", "data:"); }
        else if (match[1].startsWith("glob:")) { addHeader(headers, "script-src", "data:"); }
        else { addHeader(headers, "script-src", "'self'"); addHeader(headers, "connect-src", url); }

        // Recurse
        await scanJSFile(headers, new URL(match[1], url).toString());
    }
};

// Filter the url in the most specific way that'll still work with CSP format
const filterURL = (url: string): string | null => {
    try {
        // Remove surrounding quotes
        url = url.replace(/^[`'"]|[`'"]$/g, "");

        // Check for base64
        if (url.startsWith("data:")) { return "data:"; }

        // Check for glob
        if (url.startsWith("glob:")) { return "glob:"; }

        // Parse as new URL so that we can extract certain parts of it.
        const parsed = new URL(url);

        // If the hostname contains any invalid characters, return null.
        if (!parsed.hostname.match(/[^a-z0-9-.]/i)) { return null; }

        // If pathname has ${ in it, we'll assume it's a template and return the hostname.
        if (parsed.pathname.includes("$%7B")) { return parsed.hostname; }

        // Return hostname + pathname, skip any query strings.
        return `${parsed.hostname}${parsed.pathname}`;
    } catch (err) {
        // If we can't parse the URL, return null
        return null;
    }
};