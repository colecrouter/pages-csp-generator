import { localhost } from "../csp";
import { addHeader } from "../utils";

const serviceWorkerRegex = /navigator\.serviceWorker\.register\('(.*)'\)/;
const absoluteURLRegex = /["'`]([a-z]+:\/\/.*\.[a-z]+[a-z0-9\/]*)[\?#]?.*["'`]/;
const relativeURLRegex = /["''](?!.*\/\/)(.*)["'']/i;


const cache = new Map<string, string[]>();

export const scanJSFile = async (headers: Map<string, string[]>, url: string): Promise<void> => {
    // Check cache
    if (cache.has(url)) {
        for (const value of cache.get(url)!) {
            addHeader(headers, value[0], value[1]);
        }
        return;
    }

    // Fetch file, this will fail if its local, but we'll try anyway
    let response: Response;
    try {
        if (absoluteURLRegex.test(url)) {
            response = await fetch(url);
        } else {
            response = await fetch(new URL(url.startsWith("/") ? url.substring(1) : url, localhost).toString());
        }
    } catch (err) {
        return;
    }

    if (!response.ok) { return; }

    // Search file for urls
    const text = await response.text();
    let urls = text.match(absoluteURLRegex);
    if (!urls) { urls = []; }

    // Append to headers
    for (const value of urls) {
        const url = filterURL(value);
        if (!url) { continue; }

        addHeader(headers, "script-src", url);
        addHeader(headers, "connect-src", url);
    }

    // Cache
    cache.set(url, urls);
};

export const scanJS = async (headers: Map<string, string[]>, text: string): Promise<void> => {
    // Search file for urls
    let urls = text.match(absoluteURLRegex);
    if (!urls) { urls = []; }

    // Append to headers
    for (const value of urls) {
        const url = filterURL(value);
        if (!url) { continue; }

        addHeader(headers, "script-src", url);
        addHeader(headers, "connect-src", url);
    }
};

// Filter the url in the most specific way that'll still work with CSP format
const filterURL = (url: string): string | null => {
    try {
        // Remove surrounding quotes
        url = url.replace(/^[`'"]|[`'"]$/g, "");

        // Check for base64
        if (url.startsWith("data:")) { return "data:"; }

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