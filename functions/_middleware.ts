import { InjectCSP } from "../src";

export const onRequestGet = [InjectCSP({ InlineMethod: "nonce", InjectionMethod: "headers" })];