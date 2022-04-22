import { absoluteURLRegex, addHeader } from "../utils";

const cache = new Map<string, string[]>();
const urlRegex = /url\(['"`]?((?:[a-z]+:).*?)['"`]?\)/i;

export const scanCSSFile = async (headers: Map<string, string[]>, url: string): Promise<void> => {
    // Remove quotes surrounding url
    url = url.replace(/^['"]|['"]$/g, "");

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

    // Search file for url()
    const text = await response.text();
    const match = urlRegex.exec(text);
    const urls = match && match[1] ? match[1] : [];
    if (!urls) { return; }

    // Append to headers
    for (const value of urls) {
        addHeader(headers, "style-src", value);
    }

    // Cache
    cache.set(url, urls as string[]);
};

export const scanCSS = async (headers: Map<string, string[]>, text: string): Promise<void> => {
    // Search file for url()
    const urls = urlRegex.exec(text);
    if (!urls) { return; }
    urls.shift();


    // Append to headers
    for (const value of urls) {
        addHeader(headers, "img-src", value);
    }
};