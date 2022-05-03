import { ExistingMetaHandler, AnchorHandler, SrcHrefHandler, InsertMetaTagHandler, CSSHandler, JSHandler, InlineStyleFinder } from "./handlers";
import { CSPDirective, headersToString, parseCSP } from "./utils";

export type CSPInlineHash = 'sha256' | 'sha384' | 'sha512';
export type CSPInlineMethod = 'nonce' | CSPInlineHash;
export type CSPInjectionMethod = 'meta-tags' | 'headers';
export type CSPCacheMethod = 'none' | 'localhost' | 'all';

export interface CSPOptions {
    InjectionMethod: CSPInjectionMethod;
    InlineMethod: CSPInlineMethod;
    CacheMethod: CSPCacheMethod;
    ScanExternal?: boolean;
    RecurseJS?: boolean;
}

export let localhost: string;

const pageCache = new Map<string, Map<CSPDirective, Array<string>>>();

export const InjectCSP = (options: CSPOptions): PagesFunction<{}> => {
    return async ({ request, next }) => {
        let headers = new Map<CSPDirective, Array<string>>();
        headers.set('default-src', ["'self'"]);

        // Get existing headers
        if (request.headers.has('content-security-policy')) {
            parseCSP(options, headers, request.headers.get('content-security-policy')!);
        }

        const n = await next(); // Get next down the chain

        // Skip if we're not on a page
        if (!n.clone().headers.get("content-type")?.includes("text/html")) {
            return n;
        }

        // Cheeky fetch not being good workaround
        if (!localhost) { localhost = new URL(request.url).origin; }

        let r = n.clone();

        if (options.CacheMethod === "all" && pageCache.has(request.url)) {
            headers = pageCache.get(request.url)!;
        } else {
            // This pass serves four purposes:
            //  - It records all instances where CSP headers are required
            //  - It checks if 'unsafe-inline' is required for styles
            //  - Tt adds nonces/hashes to inline scripts (styles too, if no 'unsafe-inline' is required)
            //  - Parse any CSP headers that are present in any existing meta tags
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
        }

        if (options.InjectionMethod === "meta-tags") {
            // If method is "meta-tags", this pass adds a meta tag for the CSP directive, and adds the headers to it
            // This assumes that any existing CSP meta tags have been removed and won't interfere
            return new HTMLRewriter()
                .on("head", new InsertMetaTagHandler(options, headers))
                .transform(r);
        } else {
            const newHeaders = new Headers([...r.headers.entries()]);
            newHeaders.set("Content-Security-Policy", headersToString(options, headers));
            return new Response(r.clone().body, { ...r, headers: newHeaders });
        }
    };
};