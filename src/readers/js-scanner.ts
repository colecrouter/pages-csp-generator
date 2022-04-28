import { localhost } from "../csp";
import { absoluteURLRegex, addHeader, urlToHeader } from "../utils";

const serviceWorkerRegex = /navigator\.serviceWorker\.register\([`'"](.*?)[`'"]/gi;
const relativeURLRegex = /["'`]((?!http|https)(?!:\/\/)(?!:[0-9]+)[\/_a-z0-9.]+\.[a-z]+)[\?#]?.*?["'`]/gi;
const base64Regex = /['"`]?(data:(?<mime>[\w\/\-\.]+);(?<encoding>\w+),(?<data>.*))['"`]?/gi;
const blobRegex = /["'`]?(blob:.*)["'`]?/gi;

export const scanJSFile = async (headers: Map<string, string[]>, url: string): Promise<void> => {
    if (new URL(url).origin !== localhost) { return; }

    // Get file contents
    const response = await fetch(url);
    if (!response.ok) { return; }
    const text = await response.text();

    await scanJS(headers, url, text);
};

export const scanJS = async (headers: Map<string, string[]>, url: string, text: string): Promise<void> => {
    // Search for absolute URLs
    for (const match of text.matchAll(absoluteURLRegex)) {
        urlToHeader(headers, match[1]);
    }

    // Search for base64
    for (const match of text.matchAll(base64Regex)) {
        if (match.groups?.mime.startsWith("image/")) {
            addHeader(headers, "img-src", "data:");
        }
    }

    // Search for blob
    for (const match of text.matchAll(blobRegex)) {
        addHeader(headers, "script-src", "blob:");
        addHeader(headers, "img-src", "blob:");
    }

    // Search for relative URLs
    for (const match of text.matchAll(relativeURLRegex)) {
        urlToHeader(headers, match[1]);

        // Recurse
        // await scanJSFile(headers, new URL(match[1], url).toString());
    }

    // Search for service worker registration
    // TODO change
    for (const match of text.matchAll(serviceWorkerRegex)) {
        urlToHeader(headers, match[1], "worker-src");
    }
};