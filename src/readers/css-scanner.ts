import { localhost } from "../csp";
import { addHeader, urlToHeader } from "../utils";

const absoluteURLRegex = /["'`]?((?:http|https):\/\/[a-z0-9]+(?:\.[a-z]*)?(?::[0-9]+)?[\/a-z0-9.]*)[\?#]?.*?["'`]?/gi;
const relativeURLRegex = /url\(["']?(?!.*\/\/)(.*\.[a-z]+)["']?\)/gi;
const base64Regex = /url\(['"`]?(data:(?<mime>[\w\/\-\.+]+);?(?<encoding>\w+)?,(?<data>.*)(?![^'"`]))['"`]?\)/gi;

export const scanCSSFile = async (headers: Map<string, string[]>, url: string): Promise<void> => {
    if (new URL(url).hostname !== localhost) { return; }

    // Get file contents
    const response = await fetch(url);
    if (!response.ok) { return; }
    const text = await response.text();

    await scanCSS(headers, url, text);
};

export const scanCSS = async (headers: Map<string, string[]>, url: string, text: string): Promise<void> => {
    /// Search for absolute URLs
    for (const match of text.matchAll(absoluteURLRegex)) {
        urlToHeader(headers, match[1]);
    }

    // Search for base64
    for (const match of text.matchAll(base64Regex)) {
        if (match.groups?.mime.startsWith("image/")) {
            addHeader(headers, "img-src", "data:");
        }
    }

    // Search for relative URLs
    for (const match of text.matchAll(relativeURLRegex)) {
        urlToHeader(headers, match[1]);

        // Recurse
        // await scanJSFile(headers, new URL(match[1], url).toString());
    }
};