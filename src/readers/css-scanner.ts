import { absoluteURLRegex, addHeader } from "../utils";

const cache = new Map<string, string[]>();
const base64URLRegex = /url\(['"`]?(data:(?:image\/(?:jpeg|png|gif));base64,(?:.+))['"`]?\)/;
const URLRegex = /url\(['"`]?((?:(?!data)[a-z]+:).*?)['"`]?\)/;

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
    const match = base64URLRegex.exec(text);
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
    let urls: string[] = [];

    const match1 = base64URLRegex.exec(text);
    if (match1) { match1.shift(); urls.push("data:"); }

    const match2 = URLRegex.exec(text);
    if (match2) { match2.shift(); urls.push(...match2); }



    // Append to headers
    for (const value of urls) {
        addHeader(headers, "img-src", value);
    }
};