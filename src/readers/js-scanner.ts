import { localhost } from "../index";
import { CSPOptions } from "../types";
import { CSPHeaders, getDirectiveFromMIME, URLToHeader } from "../utils";

const srcRegex = /src\s?=\s?["'`](.*\.[a-z]+)["'`]/gi;
const blobRegex = /Blob\(.*type\s?:\s?["'`](.*)["'`].*\)/gi;
const fetchRegex = /fetch\(\s?["'`](.*?)["'`]/gi;

export const scanJSFile = async (options: CSPOptions, headers: CSPHeaders, url: URL): Promise<void> => {
    if (!options.ScanExternal && url.origin !== localhost) { return; }

    // Get file contents
    const response = await fetch(url.toString());
    if (!response.ok) { return; }
    const text = await response.text();

    // Scan contents
    await scanJS(options, headers, url, text);
};

export const scanJS = async (options: CSPOptions, headers: CSPHeaders, url: URL, text: string): Promise<void> => {
    const promises = new Array<Promise<void>>();

    // Search for src attributes
    for (const match of text.matchAll(srcRegex)) {
        promises.push(URLToHeader(options, headers, new URL(match[1], url.toString()), 'img-src'));
    }

    // Search for new Blob()
    for (const match of text.matchAll(blobRegex)) {
        console.log('blob');
        const directive = getDirectiveFromMIME(options, match[1]);
        if (directive) { promises.push(URLToHeader(options, headers, new URL('blob:'), directive));; }
    }

    // Search for fetch()
    for (const match of text.matchAll(fetchRegex)) {
        promises.push(URLToHeader(options, headers, new URL(match[1], url.toString()), 'connect-src'));
    }

    await Promise.all(promises);
};