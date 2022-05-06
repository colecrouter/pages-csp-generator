/// <reference path="./types.d.ts" />
import { ExistingMetaHandler, AnchorHandler, SrcHrefHandler, InsertMetaTagHandler, CSSHandler, JSHandler, InlineStyleFinder } from "./handlers";
import { CSPOptions } from "./types";
import { CSPDirective, HeadersToString, ParseCSP } from "./utils";

export let localhost: string;

export const InjectCSP = (unformattedOptions: Partial<CSPOptions>): PagesFunction<{}> => {
    // Apply defaults to options
    const defaults: CSPOptions = { InjectionMethod: 'headers', InlineMethod: 'nonce', UseSelf: true, ScanExternal: false };
    const options: CSPOptions = { ...defaults, ...unformattedOptions };

    return async ({ request, next }) => {
        let headers = new Map<CSPDirective, Set<string>>();

        // Get existing headers
        if (request.headers.has('content-security-policy')) {
            ParseCSP(options, headers, request.headers.get('content-security-policy')!);
        }

        const n = await next(); // Get next down the chain

        // Skip if we're not on a page
        if (!n.clone().headers.get("content-type")?.includes("text/html")) { return n; }

        // Establish what is localhost
        if (!localhost) { localhost = new URL(request.url).origin; }

        // This pass serves four purposes:
        //  - It records all instances where CSP headers are required
        //  - It checks if 'unsafe-inline' is required for styles
        //  - Tt adds nonces/hashes to inline scripts (styles too, if no 'unsafe-inline' is required)
        //  - Parse any CSP headers that are present in any existing meta tags
        let r = n.clone();
        r = new HTMLRewriter()
            .on("*", new InlineStyleFinder(options, headers))
            .on("meta", new ExistingMetaHandler(options, request, headers))
            .on('style', new CSSHandler(options, request, headers))
            .on('script', new JSHandler(options, request, headers))
            .on('a', new AnchorHandler(options, request, headers))
            .on('*', new SrcHrefHandler(options, request, headers))
            .transform(r);

        // WAIT for first pass to finish. This is required since we need to wait for all of the above handlers to finish before we can inject the CSP headers
        // Hopefully there is a better way to do this
        await r.clone().text();

        if (options.InjectionMethod === "meta-tags") {
            // If method is "meta-tags", this pass adds a meta tag for the CSP directive, and adds the headers to it
            // This assumes that any existing CSP meta tags have been removed and won't interfere
            return new HTMLRewriter()
                .on("head", new InsertMetaTagHandler(options, headers))
                .transform(r);
        } else {
            // If method is "headers", add the headers to the response
            const newHeaders = new Headers([...r.headers.entries()]);
            newHeaders.set("Content-Security-Policy", HeadersToString(options, headers));
            return new Response(r.clone().body, { ...r, headers: newHeaders });
        }
    };
};