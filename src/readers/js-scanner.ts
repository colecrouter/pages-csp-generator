import { absoluteURLRegex, addHeader } from "../utils";

const cache = new Map<string, string[]>();

export const scanJSFile = async (headers: Map<string, string[]>, url: string): Promise<void> => {
    // Check cache
    if (cache.has(url)) {
        for (const value of cache.get(url)!) {
            addHeader(headers, value[0], value[1]);
        }
        return;
    }

    // Fetch file
    const response = await fetch(url);
    if (!response.ok) { return; }

    // Search file for urls
    const text = await response.text();
    const urls = text.match(absoluteURLRegex);
    if (!urls) { return; }

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
    const urls = text.match(absoluteURLRegex);
    if (!urls) { return; }

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