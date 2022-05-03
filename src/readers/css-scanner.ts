import { CSPOptions, localhost } from "../csp";
import { addHeader, urlToHeader } from "../utils";

const absoluteURLRegex = /["'`]?((?:http|https):\/\/[a-z0-9]+(?:\.[a-z]*)?(?::[0-9]+)?[\/a-z0-9.]*)[\?#]?.*?["'`]?/gi;
const relativeURLRegex = /url\(["']?(?!.*\/\/)(.*\.[a-z]+)["']?\)/gi;
const base64Regex = /url\(['"`]?(data:(?<mime>[\w\/\-\.+]+);?(?<encoding>\w+)?,(?<data>.*)(?![^'"`]))['"`]?\)/gi;

export const scanCSSFile = async (options: CSPOptions, headers: Map<string, string[]>, url: URL): Promise<void> => {
    if (!options.ScanExternal && url.origin !== localhost) { return; }

    // Get file contents
    const response = await fetch(url.toString());
    if (!response.ok) { return; }
    const text = await response.text();

    // Scan contents
    await scanCSS(options, headers, url, text);
};

export const scanCSS = async (options: CSPOptions, headers: Map<string, string[]>, url: URL, text: string): Promise<void> => {
    const promises = new Array<Promise<void>>();

    /// Search for absolute URLs
    for (const match of text.matchAll(absoluteURLRegex)) {
        promises.push(urlToHeader(options, headers, new URL(match[1], url.toString())));
    }

    // Search for base64
    for (const match of text.matchAll(base64Regex)) {
        if (match.groups?.mime.startsWith("image/")) {
            addHeader(options, headers, "img-src", "data:");
        }
    }

    // Search for relative URLs
    for (const match of text.matchAll(relativeURLRegex)) {
        promises.push(urlToHeader(options, headers, new URL(match[1], url.toString())));

        // Recurse
        // if (options.RecurseJS) { await scanCSSFile(options, headers, new URL(match[1], url.toString())); }
    }

    await Promise.all(promises);
};