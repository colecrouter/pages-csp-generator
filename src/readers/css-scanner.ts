import { localhost } from "../csp";
import { addHeader } from "../utils";

const absoluteURLRegex = /url\(["']?([a-z]+:\/\/.*\.[a-z]+[a-z0-9\/]*)[\?#]?.*["']?\)/i; // This will match any absolute URL
const relativeURLRegex = /url\(["']?(?!.*\/\/)(.*)["']?\)/i; // This will match anything without a protocol scheme, including base64 data URIs

const cache = new Map<string, string[]>();
const URLRegex = /url\(['"`]?(.*)['"`]?\)/;

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

    // Search file for url()
    const text = await response.text();
    let urls: string[] = [];

    const match2 = URLRegex.exec(text);
    if (match2) { match2.shift(); urls.push(...match2); }

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

    const match2 = URLRegex.exec(text);
    if (match2) { match2.shift(); urls.push(...match2); }

    // Append to headers
    for (const value of urls) {
        // Switch url .extension
        let directive = "";
        switch (value.split(".").pop()!) {
            case "webp":
            case "svg":
            case "jpeg":
            case "jpg":
            case "png":
            case "gif":
            case "bmp":
            case "tiff":
                directive = "img-src";
                break;
            case "woff":
            case "woff2":
            case "eot":
            case "ttf":
            case "otf":
                directive = "font-src";
                break;
            default:
                directive = "style-src";
                break;
        }
        addHeader(headers, "img-src", value);
    }
};