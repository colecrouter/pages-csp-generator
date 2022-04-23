import { ExistingMetaHandler, AnchorHandler, SrcHrefHandler, InsertMetaTagHandler, CSSHandler, JSHandler, InlineStyleFinder } from "./handlers";
import { headersToString } from "./utils";

export type CSPInlineHash = "sha256" | "sha384" | "sha512";
export type CSPInlineMethod = "nonce" | CSPInlineHash;
export type CSPInjectionMethod = "meta-tags" | "headers";

export interface CSPOptions {
    method: CSPInjectionMethod;
    inline: CSPInlineMethod;
}

export let localhost: string;

export const InjectCSP = (options: CSPOptions): PagesFunction<{}> => {
    return async ({ request, next }) => {
        let headers = new Map<string, Array<string>>();
        headers.set('default-src', ["'self'"]);

        const n = await next(); // Get next down the chain

        // Skip if we're not on a page
        if (!n.clone().headers.get("content-type")?.includes("text/html")) {
            return n;
        }

        // Cheeky fetch not being good workaround
        if (!localhost) {
            localhost = request.url;
        }

        // This pass serves four purposes:
        //  - It records all instances where CSP headers are required
        //  - It checks if 'unsafe-inline' is required for styles
        //  - Tt adds nonces/hashes to inline scripts (styles too, if no 'unsafe-inline' is required)
        //  - Parse any CSP headers that are present in any existing meta tags
        const r = new HTMLRewriter()
            .on("*", new InlineStyleFinder(headers))
            .on("meta", new ExistingMetaHandler(request, headers))
            .on('style', new CSSHandler(request, headers, options.inline))
            .on('script', new JSHandler(request, headers, options.inline))
            .on('a', new AnchorHandler(headers))
            .on('*', new SrcHrefHandler(request, headers))
            .transform(n.clone());

        // WAIT for first pass to finish. This is required since we need to wait for all of the above handlers to finish before we can inject the CSP headers
        // Hopefully there is a better way to do this
        await r.clone().text();

        if (options.method === "meta-tags") {
            // If method is "meta-tags", this pass adds a meta tag for the CSP directive, and adds the headers to it
            // This assumes that any existing CSP meta tags have been removed and won't interfere
            return new HTMLRewriter()
                .on("head", new InsertMetaTagHandler(headers))
                .transform(r);
        } else {
            const newHeaders = new Headers([...r.headers.entries()]);
            newHeaders.set("Content-Security-Policy", headersToString(headers));
            return new Response(r.clone().body, { ...r, headers: newHeaders });
        }
    };
};