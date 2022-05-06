export interface CSPOptions {
    InjectionMethod: 'meta-tags' | 'headers';
    InlineMethod: 'sha256' | 'sha384' | 'sha512' | 'nonce';
    UseSelf: boolean;
    ScanExternal: boolean;
}

export function InjectCSP(options: Partial<CSPOptions>): PagesFunction<{}>;