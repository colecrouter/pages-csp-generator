import { localhost } from "../csp";
import { addHeader, CSPDirective } from "../utils";

const absoluteURLRegex = /url\(["']?([a-z]+:\/\/.*\.[a-z]+[a-z0-9\/]*)[\?#]?.*["']?\)/gi;
const relativeURLRegex = /url\(["']?(?!.*\/\/)(.*\.[a-z]+)["']?\)/gi;
const base64Regex = /url\(['"`]?(data:(?<mime>[\w\/\-\.+]+);?(?<encoding>\w+)?,(?<data>.*)(?![^'"`]))['"`]?\)/gi;

const cache = new Map<string, string[]>();

export const scanCSSFile = async (headers: Map<string, string[]>, url: string): Promise<void> => {
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
    for (const match of text.matchAll(absoluteURLRegex)) {
        addHeader(headers, "img-src", match[1]);
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
        await scanCSSFile(headers, new URL(match[1], url).toString());
    }

    // Cache
    // cache.set(url, matches);
};

export const scanCSS = async (headers: Map<string, string[]>, url: string, text: string): Promise<void> => {
    // Search for absolute URLs
    for (const match of text.matchAll(absoluteURLRegex)) {
        console.log(match);
        addHeader(headers, "img-src", match[1]);
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
    }

};

const getDirectiveFromExtension = (extension: string): CSPDirective => {
    switch (extension) {
        case "webp":
        case "svg":
        case "jpeg":
        case "jpg":
        case "png":
        case "gif":
        case "bmp":
        case "tiff":
            return "img-src";
        case "woff":
        case "woff2":
        case "eot":
        case "ttf":
        case "otf":
            return "font-src";
        default:
            return "style-src";
    }
};