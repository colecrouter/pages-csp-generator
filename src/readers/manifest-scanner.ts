import { WebAppManifest } from "web-app-manifest";
import { CSPOptions } from "../index";
import { CSPHeaders, URLToHeader } from "../utils";

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