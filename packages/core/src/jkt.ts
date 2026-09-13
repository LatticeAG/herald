/**
 * RFC 7638 JWK thumbprint for the card holder binding (§4):
 *   caller_jkt = b64u(SHA256(JCS({"crv":"Ed25519","kty":"OKP","x":<pk b64u>})))
 */

import { sha256Bytes } from "./digest.ts";
import { b64uEncode } from "./base64url.ts";
import { canonicalize } from "./jcs.ts";

export function callerJkt(publicKeyB64u: string): string {
  const jwk = { crv: "Ed25519", kty: "OKP", x: publicKeyB64u };
  return b64uEncode(sha256Bytes(canonicalize(jwk)));
}
