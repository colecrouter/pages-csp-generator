import { CSPOptions, localhost } from "../csp";
import { absoluteURLRegex, addHeader, urlToHeader } from "../utils";

const serviceWorkerRegex = /navigator\.serviceWorker\.register\([`'"](.*?)[`'"]/gi;
const webWorkerRegex = /Worker\([`'"](.*?)[`'"]/gi;
const relativeURLRegex = /["'`]((?!http|https)(?!:\/\/)(?!:[0-9]+)[\/_a-z0-9.]+\.[a-z]+)[\?#]?.*?["'`]/gi;
const base64Regex = /['"`]?(data:(?<mime>[\w\/\-\.]+);(?<encoding>\w+),(?<data>.*))['"`]?/gi;
const blobRegex = /["'`]?(blob:.*)["'`]?/gi;

export const scanJSFile = async (options: CSPOptions, headers: Map<string, string[]>, url: URL): Promise<void> => {
    if (!options.ScanExternal && url.origin !== localhost) { return; }

    // Get file contents
    const response = await fetch(url.toString());
    if (!response.ok) { return; }
    const text = await response.text();

    // Scan contents
    await scanJS(options, headers, url, text);
};

export const scanJS = async (options: CSPOptions, headers: Map<string, string[]>, url: URL, text: string): Promise<void> => {
    const promises = new Array<Promise<void>>();

    // Search for absolute URLs
    for (const match of text.matchAll(absoluteURLRegex)) {
        promises.push(urlToHeader(options, headers, new URL(match[1], url.toString())));
    }

    // Search for base64
    for (const match of text.matchAll(base64Regex)) {
        if (match.groups?.mime.startsWith("image/")) {
            addHeader(options, headers, "img-src", "data:");
        }
    }

    // Search for blob
    for (const match of text.matchAll(blobRegex)) {
        addHeader(options, headers, "script-src", "blob:");
        addHeader(options, headers, "img-src", "blob:");
    }

    // Search for relative URLs
    for (const match of text.matchAll(relativeURLRegex)) {
        // Search for service worker registration
        for (const match of text.matchAll(serviceWorkerRegex)) {
            promises.push(urlToHeader(options, headers, new URL(match[1], url.toString()), 'worker-src'));
        }

        // Search for web worker
        for (const match of text.matchAll(webWorkerRegex)) {
            promises.push(urlToHeader(options, headers, new URL(match[1], url.toString()), 'worker-src'));
        }

        // Recurse
        if (options.RecurseJS) {
            promises.push(scanJSFile(options, headers, new URL(match[1], url.toString())));
        }
    }

    await Promise.all(promises);
};