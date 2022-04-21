let headers: Map<string, string[]>;
const absoluteURLRegex = /^(?:[a-z]+:)?\/\//i;

export const InjectCSPTags: PagesFunction<{}> = async ({ next }): Promise<Response> => {
    try {
        headers = new Map<string, Array<string>>();
        headers.set('default-src', ["'self'"]);

        // Add nonces and build proper CSP headers
        const r = new HTMLRewriter()
            .on('style', new NonceHandler())
            .on('script', new NonceHandler())
            .on('link', new NonceHandler())
            .on('[style]', new NonceHandler())
            .on('a', new AnchorHandler())
            .on('*', new SrcHrefHandler())
            .transform(await next());

        // Add CSP headers
        return new HTMLRewriter()
            .on("meta", new TagHandler())
            .transform(r);
    } catch (e) {
        return new Response((e as Error).message, { status: 500 });
    }
};



class TagHandler {
    element(element: Element) {
        if (element.tagName !== "meta") return; { }
        if (element.getAttribute("http-equiv") !== "Content-Security-Policy") { return; }

        // Parse existing CSP header
        parseCSP(element.getAttribute("content") || "");

        // Build CSP header
        let csp = "";
        for (const [key, values] of headers) {
            csp += `${key} ${values.join(" ")}; `;
        }

        element.setAttribute("content", csp);
    }
}

// Handler for scripts and stylesheets
class NonceHandler {
    element(element: Element) {
        if (element.getAttribute("src") || element.getAttribute("href")) { return; }

        let nonce = element.getAttribute("nonce"); // Check for existing nonce

        // Set nonce if not exist
        if (!nonce) {
            nonce = randomNonce();
            element.setAttribute("nonce", nonce);
        }

        const formattedNonce = `'nonce-${nonce}'`;

        // Handle case for elements that have inline style
        if (element.getAttribute("style")) {
            addHeader("style-src", formattedNonce);
            return;
        }

        // Add nonce to list
        switch (element.tagName) {
            case "script":
                addHeader("script-src", formattedNonce);
                break;
            case "style":
                addHeader("style-src", formattedNonce);
                break;
            case "link":
                if (element.getAttribute("rel") === "stylesheet") {
                    addHeader("style-src", formattedNonce);
                }
                if (element.getAttribute("rel") === "preload") {
                    switch (element.getAttribute("as")) {

                        case "script":
                            addHeader("script-src", formattedNonce);
                            break;
                        case "style":
                            addHeader("style-src", formattedNonce);
                            break;
                    }
                }
        }
    }
};

class SrcHrefHandler {
    element(element: Element) {
        if (!element.getAttribute("src") && !element.getAttribute("href")) { return; }

        // Add nonce to list
        let url;
        let rel;
        switch (element.tagName) {
            case "script":
                url = element.getAttribute("src")!.split('?')[0];
                if (absoluteURLRegex.test(url)) {
                    addHeader("script-src", url);
                }
                break;
            case "link":
                url = element.getAttribute("href")!.split('?')[0];
                rel = element.getAttribute("rel")!;
                if (!absoluteURLRegex.test(url)) { return; }

                switch (rel) {
                    case "stylesheet":
                        addHeader("style-src", url);
                        break;
                    case "icon":
                        addHeader("img-src", url);
                        break;
                    case "prerender":
                    case "prefetch":
                        addHeader("prefetch-src", url);
                    case "preconnect":
                    case "preload":
                        switch (element.getAttribute("as")) {
                            case "script":
                                addHeader("script-src", url);
                                break;
                            case "style":
                                addHeader("style-src", url);
                                break;
                            case "font":
                                addHeader("font-src", url);
                                break;
                            case "image":
                                addHeader("img-src", url);
                                break;
                            case "audio":
                            case "video":
                                addHeader("media-src", url);
                                break;
                            case "object":
                                addHeader("object-src", url);
                                break;
                            case "worker":
                            case "document":
                                addHeader("child-src", url);
                                break;
                            case "fetch":
                                addHeader("connect-src", url);
                                break;
                            case "manifest":
                                addHeader("manifest-src", url);
                                break;
                        }
                        break;
                }
        }
    }
}

class AnchorHandler {
    element(element: Element) {
        const ping = element.getAttribute("ping");
        if (ping && absoluteURLRegex.test(ping)) { // If relative URL, skip
            addHeader("connect-src", ping);
        }
    }
}

class ImageHandler {
    element(element: Element) {
        const src = element.getAttribute("src");
        if (src && absoluteURLRegex.test(src)) { // If relative URL, skip
            addHeader("img-src", src);
        }
    }
}



const randomNonce = () => {
    for (var a = '', b = 36; a.length < 16;) a += (Math.random() * b | 0).toString(b);
    return a;
};

const addHeader = (key: string, value: string) => {
    if (value === "'none'") { headers.set(key, ["'none'"]); return; }
    if (!headers.has(key)) {
        headers.set(key, ["'self'"]);
    }
    if (value === "'self'") { return; }

    headers.get(key)!.push(value);
};

const parseCSP = (csp: string) => {
    const cspList = csp.split(";");
    for (const cspItem of cspList) {
        const [key, ...values] = cspItem.trim().split(" ");
        if (key && values) {
            for (const value of values) {
                addHeader(key, value);
            }
        }
    }
};