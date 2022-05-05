import { CSPOptions, localhost } from "../csp";
import { CSPHeaders, URLToHeader } from "../utils";

const urlRegex = /url\(["']?(.*\.[a-z]+)["']?\)/gi;

export const scanCSSFile = async (options: CSPOptions, headers: CSPHeaders, url: URL): Promise<void> => {
    if (!options.ScanExternal && url.origin !== localhost) { return; }

    // Get file contents
    const response = await fetch(url.toString());
    if (!response.ok) { return; }
    const text = await response.text();

    // Scan contents
    await scanCSS(options, headers, url, text);
};

export const scanCSS = async (options: CSPOptions, headers: CSPHeaders, url: URL, text: string): Promise<void> => {
    const promises = new Array<Promise<void>>();

    // Search for relative URLs
    for (const match of text.matchAll(urlRegex)) {
        promises.push(URLToHeader(options, headers, new URL(match[1], url.toString()), 'img-src'));
    }

    await Promise.all(promises);
};