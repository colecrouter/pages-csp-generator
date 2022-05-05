import { WebAppManifest } from "web-app-manifest";
import { CSPOptions, localhost } from "../csp";
import { AddHeader, CSPHeaders, URLToHeader } from "../utils";

const absoluteURLRegex = /["'`]?((?:http|https):\/\/[a-z0-9]+(?:\.[a-z]*)?(?::[0-9]+)?[\/a-z0-9.]*)[\?#]?.*?["'`]?/gi;
const relativeURLRegex = /url\(["']?(?!.*\/\/)(.*\.[a-z]+)["']?\)/gi;
const base64Regex = /url\(['"`]?(data:(?<mime>[\w\/\-\.+]+);?(?<encoding>\w+)?,(?<data>.*)(?![^'"`]))['"`]?\)/gi;

export const scanManifestFile = async (options: CSPOptions, headers: CSPHeaders, url: URL): Promise<void> => {
    // Get file contents
    const response = await fetch(url.toString());
    if (!response.ok) { return; }
    const text = await response.text();

    // Scan contents
    await scanManifest(options, headers, url, text);
};

export const scanManifest = async (options: CSPOptions, headers: CSPHeaders, url: URL, text: string): Promise<void> => {
    const manifest = JSON.parse(text);
    manifest as WebAppManifest;

    for (const value of Object.entries(manifest.icons)) {
        URLToHeader(options, headers, url, 'img-src');
    };
};