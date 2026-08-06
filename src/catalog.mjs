/**
 * TRUST — test catalog.
 *
 * Single source of truth for test metadata. Probes emit IDs; the catalog turns an
 * ID into a category and a purpose statement, and categories into trust domains.
 * Adding a probe means adding one catalog entry — nothing else in the report changes.
 */

export const CATALOG = {
  // ── Web / infrastructure (passive) ──────────────────────────────────
  "WEB-CONFIG": { category: "Web Hardening", purpose: "Validate that the passive web surface is configured for testing." },
  "WEB-HEADER-STRICT-TRANSPORT-SECURITY": { category: "Web Hardening", purpose: "Verify the application enforces HTTPS via HTTP Strict Transport Security, preventing protocol downgrade and cookie hijacking." },
  "WEB-HEADER-CONTENT-SECURITY-POLICY": { category: "Web Hardening", purpose: "Verify a Content Security Policy is deployed to mitigate cross-site scripting, data injection and clickjacking." },
  "WEB-HEADER-X-CONTENT-TYPE-OPTIONS": { category: "Web Hardening", purpose: "Verify the server prevents MIME-type sniffing, which can turn an upload into stored XSS." },
  "WEB-HEADER-REFERRER-POLICY": { category: "Web Hardening", purpose: "Verify referrer leakage is controlled so sensitive URL parameters are not sent to third parties." },
  "WEB-HEADER-PERMISSIONS-POLICY": { category: "Web Hardening", purpose: "Verify unused browser capabilities (camera, microphone, geolocation) are disabled to reduce attack surface." },
  "WEB-CLICKJACKING": { category: "Clickjacking", purpose: "Verify the application cannot be embedded in an unauthorised iframe, preventing UI-redressing attacks." },
  "WEB-FRAME-ANCESTORS": { category: "Clickjacking", purpose: "Verify CSP frame-ancestors is restricted to the exact approved parent origins." },
  "WEB-TLS-VERSION": { category: "Web Hardening", purpose: "Verify the server negotiates TLS 1.2 or higher and rejects deprecated protocol versions vulnerable to downgrade attacks." },
  "WEB-TLS-CERTIFICATE": { category: "Web Hardening", purpose: "Verify the server presents a certificate that validates against the public trust store." },
  "WEB-COOKIE-FLAGS": { category: "Web Hardening", purpose: "Verify session cookies carry Secure, HttpOnly and SameSite attributes to prevent interception, XSS theft and CSRF." },
  "WEB-CORS-POLICY": { category: "Web Hardening", purpose: "Verify the CORS policy does not reflect arbitrary origins or combine a wildcard with credentials." },
  "WEB-RATE-LIMIT": { category: "Web Hardening", purpose: "Verify server-side rate limiting is enforced to mitigate brute-force, credential stuffing and denial-of-service." },
  "WEB-OPEN-REDIRECT": { category: "Web Hardening", purpose: "Verify the application does not follow unvalidated redirect parameters, preventing phishing from a trusted domain." },
  "WEB-TOKEN-STORAGE": { category: "Web Hardening", purpose: "Verify authentication tokens are not written to localStorage or sessionStorage where any XSS payload could steal them." },
  "WEB-SOURCE-MAPS": { category: "Sensitive File Exposure", purpose: "Verify production JavaScript bundles do not ship source maps that expose original source code." },
  "WEB-HTTP-METHODS": { category: "Web Hardening", purpose: "Verify dangerous HTTP methods such as TRACE, PUT and DELETE are not enabled, keeping the write surface as narrow as the application intends." },
  "WEB-SERVER-BANNER": { category: "Web Hardening", purpose: "Verify response headers do not advertise software versions, which hand an attacker a shortlist of known vulnerabilities." },
  "WEB-SUBRESOURCE-INTEGRITY": { category: "Web Hardening", purpose: "Verify third-party scripts are pinned with subresource integrity, so a compromised CDN cannot execute arbitrary code in the application." },
  "WEB-COOKIE-SCOPE": { category: "Web Hardening", purpose: "Verify cookies are scoped to the exact host rather than the registrable domain, so they are not sent to every sibling subdomain." },
  "WEB-CACHE-CONTROL": { category: "Web Hardening", purpose: "Verify responses that set cookies are not publicly cacheable, so a shared cache cannot serve one user's response to another." },
  "WEB-DIRECTORY-LISTING": { category: "Sensitive File Exposure", purpose: "Verify directory browsing is disabled, so the contents of asset and upload paths are not enumerable." },

  // ── API / authorisation (authenticated) ─────────────────────────────
  "API-CONFIG": { category: "Authorization — API", purpose: "Validate that API probe configuration is complete enough for authorisation testing." },
  "API-CROSS-USER": { category: "Authorization — API", purpose: "Test whether User B can read User A's record by object ID, validating per-record ownership enforcement." },
  "API-UNSCOPED-LIST": { category: "Authorization — API", purpose: "Test whether list queries return records belonging to other users, exposing cross-tenant data without owner scoping." },
  "API-PERMISSION-MUTATION": { category: "Authorization — API", purpose: "Test whether a non-admin user can invoke mutations that modify permissions or role mappings, validating write-level RBAC." },
  "API-USERID-SPOOF": { category: "Identity Spoofing", purpose: "Test whether the API accepts a client-supplied user identifier, allowing any authenticated user to act as another." },
  // Error handling belongs to Infrastructure, not LLM Safety — the "Information Disclosure"
  // category is reserved for what an agent says about itself.
  "API-ERROR-DISCLOSURE": { category: "Error Handling", purpose: "Test whether API errors leak stack traces, SQL fragments or internal hostnames to unprivileged callers." },
  "API-INVENTORY-EXPOSED": { category: "API Surface", purpose: "Test whether the API specification or a GraphQL console is reachable without authentication, handing an attacker the full surface." },
  "API-EXCESSIVE-DATA": { category: "Data Minimisation", purpose: "Test whether ordinary reads return credential, secret or internal-only fields the client has no business receiving." },
  "API-QUERY-COST": { category: "Resource Limits", purpose: "Test whether a single request can multiply server work without limit, by asking for hundreds of aliased fields in one query." },

  // ── Session lifecycle ───────────────────────────────────────────────
  "SESSION-LOGOUT": { category: "Session Lifecycle", purpose: "Verify a token stops working once its session is ended, so a stolen credential can actually be withdrawn." },
  "SESSION-EXPIRED-TOKEN": { category: "Session Lifecycle", purpose: "Verify an expired token is rejected, confirming the exp claim is validated on every request." },

  // ── Token hygiene (offline claim inspection, no requests) ───────────
  "TOKEN-CONFIG": { category: "Token Hygiene", purpose: "Validate that tokens are available and decodable for claim inspection." },
  "TOKEN-ALG": { category: "Token Hygiene", purpose: "Verify tokens declare a strong signing algorithm and are not unsigned or vulnerable to algorithm confusion." },
  "TOKEN-LIFETIME": { category: "Token Hygiene", purpose: "Verify access tokens carry a bounded expiry, so a leaked credential has a limited useful life." },
  "TOKEN-FRESHNESS": { category: "Token Hygiene", purpose: "Confirm the supplied test tokens are still valid, so authenticated findings reflect enforced controls rather than rejected credentials." },
  "TOKEN-CLAIMS": { category: "Token Hygiene", purpose: "Verify tokens are bound to an issuer and an audience, so a token minted elsewhere cannot be replayed against this API." },
  "TOKEN-SCOPE": { category: "Token Hygiene", purpose: "Verify the test identities hold least-privilege scope, since authorisation results obtained with an admin token overstate the strength of the control." },
  "TOKEN-IDENTITY-DISTINCT": { category: "Test Integrity", purpose: "Verify the two test identities are genuinely different principals — if they are not, every cross-user isolation result in the run is vacuous." },
  "TOKEN-TENANT-DISTINCT": { category: "Test Integrity", purpose: "Verify the two test identities sit in different tenants, so cross-tenant isolation is actually exercised." },

  // ── Input handling (OWASP A03) ──────────────────────────────────────
  "INJECT-CONFIG": { category: "Injection", purpose: "Validate that the input-handling probe suite has a reachable target." },
  "INJECT-REFLECTED-XSS": { category: "Injection", purpose: "Test whether user input is reflected into HTML without encoding, the precondition for cross-site scripting." },
  "INJECT-SQL-ERROR": { category: "Injection", purpose: "Test whether inert quote payloads surface database errors, indicating user input reaches a query uncontrolled." },
  "INJECT-TEMPLATE": { category: "Injection", purpose: "Test whether user input is evaluated as a template expression, which typically leads to server-side code execution." },
  "INJECT-PATH-TRAVERSAL": { category: "Injection", purpose: "Test whether file parameters can escape their base directory and return arbitrary server files." },
  "INJECT-CRLF-HEADER": { category: "Injection", purpose: "Test whether encoded newlines in a parameter can inject a response header, enabling cache poisoning and session fixation." },
  "INJECT-HOST-HEADER": { category: "Injection", purpose: "Test whether absolute URLs are built from the caller-supplied Host header, which turns password-reset links into phishing links." },
  "INJECT-SSRF": { category: "Injection", purpose: "Test whether URL parameters are fetched server-side, the entry point for reaching internal services and cloud metadata." },
  "API-INTROSPECTION": { category: "Authorization — API", purpose: "Test whether GraphQL schema introspection is exposed to ordinary users, handing an attacker the full API surface." },
  "AUTH-PASSWORD-BYPASS": { category: "Authentication", purpose: "Verify the identity provider rejects direct username/password authentication so all users must pass through federated SSO." },

  // ── Server-side token validation (the live half of token hygiene) ───
  "JWT-CONFIG": { category: "Token Hygiene", purpose: "Validate that a JWT and an authenticated endpoint are available to test server-side verification." },
  "JWT-ALG-NONE": { category: "Token Hygiene", purpose: "Verify the API rejects a token declaring alg:none — a server that accepts one has no authentication, because any caller can mint any identity." },
  "JWT-SIGNATURE": { category: "Token Hygiene", purpose: "Verify the API rejects a token whose signature does not verify, confirming signatures are checked rather than claims merely being read." },
  "JWT-CLAIMS-TAMPERED": { category: "Token Hygiene", purpose: "Verify the API rejects claims the signature does not cover, so privileges cannot be self-granted by editing a token body." },
  "JWT-UNKNOWN-KID": { category: "Token Hygiene", purpose: "Verify the API rejects a token naming a signing key absent from the issuer's published key set, rather than falling back to a default key." },
  "JWT-AUDIENCE-BINDING": { category: "Token Hygiene", purpose: "Validate that cross-service token reuse can be tested — a token is minted for one service, and a neighbour that ignores the audience claim accepts it too." },
  "JWT-VERIFICATION": { category: "Token Hygiene", purpose: "Summarise whether token verification is enforced at all — every authorisation result in a run depends on the identity being trustworthy." },

  // ── Request forgery and over-binding ────────────────────────────────
  "API-CSRF": { category: "Authorization — API", purpose: "Verify state-changing requests reject an untrusted origin, so a page the user did not author cannot act with their session." },
  "API-MASS-ASSIGNMENT": { category: "Authorization — API", purpose: "Verify privileged fields — role, tenant, owner — cannot be set from the request payload, the write-side twin of identity spoofing." },
  "INJECT-BODY": { category: "Injection", purpose: "Verify JSON body fields are validated and encoded on the same path as query parameters, since a POST-first API is otherwise untested." },

  // ── Storage boundaries beyond the prefix check ──────────────────────
  "STORAGE-PATH-TRAVERSAL": { category: "Authorization — Storage", purpose: "Verify object keys cannot escape the caller's prefix through traversal sequences, in any encoding — a prefix comparison against an un-normalised key is not a boundary." },
  "STORAGE-SIGNED-URL": { category: "Authorization — Storage", purpose: "Verify a signed URL cannot be altered or its expiry extended, confirming the signature is verified rather than the query string merely parsed." },

  // ── Agent behaviour over more than one turn ─────────────────────────
  "AGENT-MULTI-TURN-INJECTION": { category: "Prompt Security", purpose: "Verify an instruction planted in an earlier turn does not control later answers, since a guardrail that reads only the current turn never sees it." },
  "AGENT-TOOL-ABUSE": { category: "Agent Authorization", purpose: "Verify tools cannot be steered outside the caller's entitlement — a tool that trusts the agent's arguments inherits every injection the agent is subject to." },

  // ── Identity provider configuration (unauthenticated) ───────────────
  "IDP-CONFIG": { category: "Authentication", purpose: "Validate that identity-provider configuration is present for IdP posture testing." },
  "IDP-DISCOVERY": { category: "Authentication", purpose: "Verify the provider publishes a readable OIDC discovery document over an HTTPS issuer, which is what makes the remaining IdP checks conclusive rather than probable." },
  "IDP-PKCE-SUPPORTED": { category: "Authentication", purpose: "Verify the provider supports PKCE with S256, without which a public client cannot protect an authorisation code in transit." },
  "IDP-IMPLICIT-FLOW": { category: "Authentication", purpose: "Verify the implicit flow is not offered, since it returns tokens in the URL fragment where browser history, referrers and logs retain them." },
  "IDP-CLIENT-AUTH": { category: "Authentication", purpose: "Verify that a token endpoint accepting unauthenticated clients is compensated by PKCE, so an intercepted authorisation code cannot simply be redeemed." },
  "IDP-AUTHORIZE-REQUEST": { category: "Authentication", purpose: "Verify the application itself requests an authorisation code with an S256 challenge — what the provider supports and what the application asks for are different questions." },
  "IDP-PASSWORD-GRANT": { category: "Authentication", purpose: "Verify the user pool refuses direct username/password authentication, so federated sign-in and everything attached to it cannot be bypassed." },
  "IDP-SESSION-FIXATION": { category: "Session Lifecycle", purpose: "Verify the session identifier changes on authentication, so a pre-set session cannot be adopted by the victim." },
  "IDP-CODE-VERIFIER-CLEARED": { category: "Session Lifecycle", purpose: "Verify the PKCE code verifier is cleared once the callback completes, so it cannot be reused from a persisted cookie." },

  // ── Declared isolation boundaries ───────────────────────────────────
  "ISOLATION-CONFIG": { category: "Authorization — API", purpose: "Validate that declarative isolation boundaries are configured. Declared boundaries carry their own category, since a boundary may be an API, storage or identity control." },

  // ── Storage ─────────────────────────────────────────────────────────
  "STORAGE-CONFIG": { category: "Authorization — Storage", purpose: "Validate that storage configuration is complete for isolation testing." },
  "STORAGE-PUBLIC-LISTING": { category: "Authorization — Storage", purpose: "Test whether the storage bucket or container can be listed or read without credentials." },
  "STORAGE-CROSS-TENANT": { category: "Authorization — Storage", purpose: "Test whether a user in Tenant A can list or read objects under Tenant B's prefix, validating multi-tenant storage isolation." },
  "STORAGE-CROSS-USER": { category: "Authorization — Storage", purpose: "Test whether one user can read another user's files in the protected prefix, even within the same tenant." },

  // ── AI agent runtime ────────────────────────────────────────────────
  "AGENT-CONFIG": { category: "Agent Authorization", purpose: "Validate that agent runtime configuration is complete for AI security testing." },
  "AGENT-DENIED-TARGET": { category: "Agent Authorization", purpose: "Test whether the runtime rejects invocation of an agent the caller is not entitled to use, validating the agent allowlist." },
  "AGENT-IDENTITY-SPOOF": { category: "Agent Identity", purpose: "Test whether the runtime honours a caller-supplied user identifier, which would allow impersonation and ACL bypass." },
  "AGENT-DIRECT-INJECTION": { category: "Prompt Security", purpose: "Test whether the agent follows instructions injected directly into the user turn, indicating weak instruction hierarchy." },
  "AGENT-INDIRECT-INJECTION": { category: "Prompt Security", purpose: "Test whether the agent follows instructions embedded in untrusted retrieved content, indicating insufficient data/instruction separation." },
  "AGENT-LINK-SAFETY": { category: "Prompt Security", purpose: "Test whether the agent can be induced to emit dangerous URI schemes (javascript:, data:text/html, vbscript:) that execute in the browser." },
  "AGENT-CROSS-SESSION": { category: "Session Isolation", purpose: "Test whether User B can reuse User A's session identifier to inherit conversation context, violating session ownership." },
  "AGENT-MEMORY-ISOLATION": { category: "Session Isolation", purpose: "Test whether conversation memory written by User A can be recalled by User B, validating user-scoped memory." },
  "AGENT-ACL-BYPASS": { category: "Agent ACL", purpose: "Where hierarchy bypass is reachable, test whether the sub-agent enforces entitlements itself or relies solely on the orchestrator." },
  "AGENT-GUARDRAIL-BYPASS": { category: "Agent Guardrails", purpose: "Where hierarchy bypass is reachable, test whether content guardrails (PII, topic policy) apply at sub-agent level or only at the entry point." },
  "AGENT-SYSTEM-PROMPT-LEAK": { category: "Information Disclosure", purpose: "Test whether the agent can be induced to reveal its system prompt, which encodes internal instructions and security boundaries." },
  "AGENT-CREDENTIAL-LEAK": { category: "Information Disclosure", purpose: "Test whether the agent discloses API keys, connection strings or internal endpoints when asked directly." },
  "AGENT-TOOL-SCHEMA-LEAK": { category: "Information Disclosure", purpose: "Test whether the agent reveals its tool definitions, MCP server schemas or internal function signatures." },

  // ── Mobile ──────────────────────────────────────────────────────────
  "MOBILE-CONFIG": { category: "Mobile Platform", purpose: "Validate that mobile probe configuration is complete." },
  "MOBILE-DEEP-LINK": { category: "Mobile Platform", purpose: "Verify deep-link parameters are validated server-side and cannot redirect the app to an attacker-controlled destination." },
  "MOBILE-UNIVERSAL-LINK": { category: "Mobile Platform", purpose: "Verify the app-site association files are served correctly and scoped, so link handling cannot be hijacked." },
  "MOBILE-CERT-PINNING": { category: "Mobile Platform", purpose: "Verify certificate pinning is enforced so a proxy with a rogue certificate cannot intercept API traffic." },
  "MOBILE-ROOT-DETECTION": { category: "Mobile Platform", purpose: "Verify the API refuses traffic that identifies itself as originating from a rooted or jailbroken device." },
  "MOBILE-LOCAL-STORAGE": { category: "Mobile Platform", purpose: "Verify credentials are held in the platform keystore rather than plaintext files in the app sandbox." },
};

/** Prefix rules for dynamically generated IDs. */
const PREFIX_RULES = [
  {
    prefix: "WEB-EXPOSED-",
    meta: (id) => ({
      category: "Sensitive File Exposure",
      purpose: `Verify that ${id.slice("WEB-EXPOSED-".length).toLowerCase().replace(/-/g, "/")} is not publicly accessible, preventing credential or source-code leakage.`,
    }),
  },
  {
    prefix: "JWT-AUDIENCE-",
    meta: (id) => ({
      category: "Token Hygiene",
      purpose: `Test whether ${id.slice("JWT-AUDIENCE-".length)} accepts a token minted for a different service — a service that verifies only the signature accepts every token its issuer ever produced.`,
    }),
  },
  {
    prefix: "AGENT-ENDPOINT-",
    meta: (id) => ({
      category: "Agent Hierarchy",
      purpose: `Test whether the declared agent endpoint ${id.slice("AGENT-ENDPOINT-".length)} enforces the trust boundary its configuration claims for it.`,
    }),
  },
  {
    prefix: "AGENT-HIERARCHY-",
    meta: (id) => ({
      category: "Agent Hierarchy",
      purpose: `Test whether an external user token can invoke ${id.slice("AGENT-HIERARCHY-".length)} directly, bypassing the orchestrator's ACL checks and guardrails.`,
    }),
  },
  {
    prefix: "STORAGE-CROSS-TENANT-",
    meta: () => CATALOG["STORAGE-CROSS-TENANT"],
  },
  {
    prefix: "STORAGE-CROSS-USER-",
    meta: () => CATALOG["STORAGE-CROSS-USER"],
  },
  {
    prefix: "API-REST-",
    meta: (id) => ({
      category: "Authorization — API",
      purpose: `Test authorisation behaviour of the ${id.slice("API-REST-".length).toLowerCase()} endpoint under a second identity.`,
    }),
  },
];

/**
 * Renamed test IDs. A finding ID is a public API — partner dashboards and CI gates
 * key on it — so an ID is never simply changed: the old one is aliased here and the
 * rename ships in a major version. The full contract is in the README.
 *
 *   "OLD-ID": "NEW-ID"
 */
export const DEPRECATED_IDS = {};

/** Resolve an ID through the alias map. */
export function canonicalId(id) {
  const seen = new Set();
  let current = id;
  while (DEPRECATED_IDS[current] && !seen.has(current)) {
    seen.add(current);
    current = DEPRECATED_IDS[current];
  }
  return current;
}

export function getTestMeta(id) {
  const canonical = canonicalId(id);
  if (CATALOG[canonical]) return CATALOG[canonical];
  for (const rule of PREFIX_RULES) {
    if (canonical.startsWith(rule.prefix)) return rule.meta(canonical);
  }
  return { category: "Other", purpose: "" };
}

/**
 * Register metadata for probes that ship outside this package, so partner tests
 * score, group and report exactly like built-in ones.
 *
 *   registerCatalogEntries({ "ACME-SSO-CLOCK-SKEW": { category: "Authentication",
 *     purpose: "Verify the assertion window rejects a skewed clock." } });
 *
 * A category with no domain mapping falls back to "Platform"; register the mapping
 * (and a root cause) when the tests describe a new architectural area.
 */
export function registerCatalogEntries(entries) {
  for (const [id, meta] of Object.entries(entries)) {
    if (!meta?.category) throw new TypeError(`Catalog entry ${id} needs a category`);
    if (!meta?.purpose) throw new TypeError(`Catalog entry ${id} needs a purpose`);
    // `supersedes` lets a probe written against the real schema absorb the generic built-in it
    // replaces, so a team that keeps both does not read the same control twice.
    CATALOG[id] = { category: meta.category, purpose: meta.purpose, ...(meta.supersedes ? { supersedes: [meta.supersedes].flat() } : {}) };
  }
  return CATALOG;
}

/** Map a new category onto a trust domain (existing or new). */
export function registerDomains(mapping) {
  Object.assign(TRUST_DOMAINS, mapping);
  for (const domain of Object.values(mapping)) {
    if (!DOMAIN_ORDER.includes(domain)) DOMAIN_ORDER.splice(DOMAIN_ORDER.length - 1, 0, domain);
  }
  return TRUST_DOMAINS;
}

/** Give a domain its architectural root-cause statement. */
export function registerRootCauses(mapping) {
  Object.assign(ROOT_CAUSE_MAP, mapping);
  return ROOT_CAUSE_MAP;
}

/**
 * Declare a control-failure chain of your own.
 *
 * Every other catalogue facet is extensible and this one was not, so an org whose architecture
 * has a chain the built-ins do not describe had no way to say so. `requires` / `anyOf` /
 * `alsoAnyOf` take regular expressions or strings; a string is matched as a whole ID, which is
 * the common case and avoids anchoring mistakes that silently never match.
 */
export function registerAttackPaths(paths) {
  const escape = (text) => String(text).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const asPatterns = (list) => (list ?? []).map((entry) => (entry instanceof RegExp ? entry : new RegExp(`^${escape(entry)}$`)));
  for (const path of [paths].flat().filter(Boolean)) {
    if (!path.id || !path.name) throw new TypeError("registerAttackPaths requires id and name on every path");
    ATTACK_PATHS.push({
      blocker: false,
      steps: [],
      impact: "",
      ...path,
      requires: asPatterns(path.requires),
      ...(path.anyOf ? { anyOf: asPatterns(path.anyOf) } : {}),
      ...(path.alsoAnyOf ? { alsoAnyOf: asPatterns(path.alsoAnyOf) } : {}),
    });
  }
  return ATTACK_PATHS;
}

/** Collapse a family of near-identical passing titles into one statement. */
export function registerSummaryRules(rules) {
  SUMMARY_RULES.push(...rules);
  return SUMMARY_RULES;
}

/**
 * Canonical remediation actions.
 *
 * A `fix` key on a finding says "this closes with the same change as everything else carrying
 * this key". The report groups on it, so a team sees the piece of work rather than a list of
 * symptoms — seven header controls are one edge configuration change, not seven tickets.
 */
export const FIX_ACTIONS = {
  "edge-response-headers": "Configure security response headers at the edge (CDN, Amplify customHeaders, or the reverse proxy) so every response carries them.",
  "resolver-owner-scoping": "Add owner/tenant scoping in the resolver, derived from the verified token claim rather than from a client-supplied field.",
  "token-verification": "Verify the token — algorithm, signature, key and expiry — before any claim in it is used for authorisation.",
  "storage-prefix-policy": "Scope the storage policy to the caller's identity or tenant prefix, and enforce it in the credential-vending layer rather than in the client.",
  "agent-tier-boundary": "Restrict each agent runtime to its parent tier, and enforce entitlements inside every agent that touches data.",
  "idp-client-config": "Correct the identity-provider app client configuration: PKCE with S256, authorisation-code flow only, and no parallel password grant.",
};

/**
 * Tags, for filtering a run and for mapping controls to an external framework.
 *
 * Derived from the category rather than stored per control: a category already says what kind
 * of control this is, and one mapping that stays in step beats ninety-seven that drift. A
 * partner registering their own category can register its tags alongside.
 */
export const CATEGORY_TAGS = {
  "Identity Spoofing": ["owasp-api-1", "authz", "identity"],
  "Authorization — API": ["owasp-api-1", "owasp-api-3", "authz"],
  "Authorization — Storage": ["owasp-api-1", "authz", "storage"],
  "Data Minimisation": ["owasp-api-3", "data"],
  Authentication: ["owasp-api-2", "authn"],
  "Session Lifecycle": ["owasp-api-2", "authn", "session"],
  "Token Hygiene": ["owasp-api-2", "authn", "token"],
  "Resource Limits": ["owasp-api-4", "availability"],
  "API Surface": ["owasp-api-9", "surface"],
  "Error Handling": ["owasp-api-8", "disclosure"],
  Injection: ["owasp-api-10", "injection", "input"],
  "Web Hardening": ["hardening", "headers", "transport"],
  Clickjacking: ["hardening", "browser"],
  "Sensitive File Exposure": ["disclosure", "surface"],
  "Mobile Platform": ["mobile"],
  "Agent Authorization": ["ai", "authz", "agent"],
  "Agent Hierarchy": ["ai", "agent", "boundary"],
  "Agent Identity": ["ai", "identity"],
  "Prompt Security": ["ai", "llm", "injection"],
  "Information Disclosure": ["ai", "llm", "disclosure"],
  "Test Integrity": ["assessment"],
};

/**
 * Which control replaces which.
 *
 * A partner writing a probe against their real schema often covers exactly what a built-in
 * covers generically — and keeping both is right, because the specific one is better evidence
 * while the generic one still runs everywhere. Declaring `supersedes` says they are one control,
 * so the report stops presenting two.
 */
export function supersededBy() {
  const map = new Map();
  for (const [id, meta] of Object.entries(CATALOG)) {
    for (const replaced of meta.supersedes ?? []) map.set(replaced, id);
  }
  return map;
}

/** Register tags for a category that ships outside this package. */
export function registerTags(mapping) {
  Object.assign(CATEGORY_TAGS, mapping);
  return CATEGORY_TAGS;
}

/** Every tag on a control: its category's tags, plus its trust domain in slug form. */
export function tagsFor(id, category) {
  const cat = category ?? getTestMeta(id).category;
  const domainTag = getDomain(cat).toLowerCase().replace(/[^a-z0-9]+/g, "-");
  return [...new Set([...(CATEGORY_TAGS[cat] ?? []), domainTag])];
}

/** Every known test, flattened — used by `trust catalog` and for docs generation. */
export function listCatalog() {
  return Object.entries(CATALOG)
    .map(([id, meta]) => ({ id, ...meta, domain: getDomain(meta.category), tags: tagsFor(id, meta.category) }))
    .sort((a, b) => a.domain.localeCompare(b.domain) || a.id.localeCompare(b.id));
}

/** Category → trust domain. The abstraction that lets the report speak architecturally. */
export const TRUST_DOMAINS = {
  "Web Hardening": "Infrastructure",
  Clickjacking: "Infrastructure",
  "Sensitive File Exposure": "Infrastructure",
  "Mobile Platform": "Infrastructure",
  "Error Handling": "Infrastructure",
  "API Surface": "Infrastructure",
  "Resource Limits": "Infrastructure",
  Injection: "Input Handling",
  "Authorization — API": "Authorization",
  "Authorization — Storage": "Authorization",
  "Data Minimisation": "Authorization",
  Authentication: "Authentication",
  "Session Lifecycle": "Authentication",
  "Token Hygiene": "Authentication",
  "Test Integrity": "Assessment Integrity",
  "Identity Spoofing": "Identity Binding",
  "Agent Identity": "Identity Binding",
  "Agent Authorization": "AI Runtime",
  "Agent Hierarchy": "AI Runtime",
  "Agent ACL": "AI Runtime",
  "Agent Guardrails": "AI Runtime",
  "Session Isolation": "AI Runtime",
  "Prompt Security": "LLM Safety",
  "Information Disclosure": "LLM Safety",
  Other: "Platform",
};

export function getDomain(category) {
  return TRUST_DOMAINS[category] ?? "Platform";
}

export function domainForId(id) {
  return getDomain(getTestMeta(id).category);
}

/** Architectural observations, not individual fixes. */
/**
 * Root causes at category granularity, consulted before the domain-level map. A domain like
 * Infrastructure spans transport, headers, error handling and caching; attributing an error
 * disclosure to "browser and transport hardening" misdescribes the evidence.
 */
export const CATEGORY_ROOT_CAUSE_MAP = {
  "Error Handling": "Detailed server-side errors are returned to clients without a sanitised error boundary",
  "API Surface": "The API's own description is reachable without authentication",
  "Resource Limits": "A single request can multiply server work without a cost or depth budget",
  "Data Minimisation": "Responses are serialised whole rather than shaped per role",
  "Session Lifecycle": "Sessions cannot be withdrawn once issued",
  "Token Hygiene": "Token claims are not constrained to a short life, a bound audience and least privilege",
  "Test Integrity": "The test setup does not support the conclusions this report can draw",
  Injection: "Untrusted input is not consistently validated, encoded or kept out of interpreters",
  "Sensitive File Exposure": "Deployment artefacts are served alongside the application",
  "Mobile Platform": "Server-side controls for mobile clients are incomplete",
};

export const ROOT_CAUSE_MAP = {
  "Identity Binding": "Client-controlled identity is trusted instead of server-side token claims",
  Authentication: "Authentication flow configuration permits a bypass or a weaker path",
  Authorization: "Authorisation metadata is overly exposed or insufficiently scoped",
  "AI Runtime": "Agent orchestration boundaries are not fully enforced",
  "LLM Safety": "LLM input/output boundaries are not fully secured",
  "Input Handling": "Untrusted input is not consistently validated, encoded or kept out of interpreters",
  "Assessment Integrity": "The test setup itself weakens the evidence this report can offer",
  Infrastructure: "Browser and transport security hardening is incomplete",
  Platform: "Platform-level security controls need attention",
};

/** Narrative security flow — identity first, then what it unlocks. */
export const DOMAIN_ORDER = [
  "Assessment Integrity",
  "Identity Binding",
  "Authentication",
  "Authorization",
  "Input Handling",
  "AI Runtime",
  "LLM Safety",
  "Infrastructure",
  "Platform",
];

/**
 * Correlated control-failure chains — how independently verified failures combine.
 *
 * Naming matters here: each component control is proven to have failed, but no run executes
 * the chain end to end. Calling it a "confirmed attack path" would claim more than the
 * evidence supports. It becomes one only when TRUST can traverse the chain in a single run.
 *
 * A scanner lists findings; an assessment explains what they add up to. Each path fires only
 * when **every** required control is actually failing in this run, so the claim is derived
 * from evidence already in the report rather than inferred. No model judges this.
 *
 *   requires  finding-ID patterns that must all be FAILING for the path to be reported
 *   anyOf     at least one of these must be failing (optional widening of a step)
 *   impact    what an attacker achieves — stated in business terms, not test terms
 *   blocker   whether the path alone should block a release
 */
export const ATTACK_PATHS = [
  {
    id: "PATH-IMPERSONATION-TO-TENANT-DATA",
    name: "Impersonation → orchestrator bypass → cross-tenant data exposure",
    steps: [
      "Identity is taken from the request instead of the verified token",
      "A sub-agent accepts an end-user token directly, skipping the orchestrator",
      "That sub-agent does not enforce entitlements itself",
      "Storage or list APIs are not scoped to the caller's tenant",
    ],
    requires: [/^(API|AGENT)-IDENTITY-SPOOF$|^API-USERID-SPOOF$/],
    anyOf: [/^AGENT-HIERARCHY-/, /^AGENT-ACL-BYPASS$/],
    alsoAnyOf: [/^STORAGE-CROSS-TENANT/, /^API-UNSCOPED-LIST$/],
    impact: "An authenticated user can act as another identity and reach data belonging to another tenant.",
    blocker: true,
  },
  {
    id: "PATH-GUARDRAIL-BYPASS-TO-DISCLOSURE",
    name: "Sub-agent bypass → guardrail bypass → sensitive disclosure",
    steps: [
      "A sub-agent can be invoked directly with an end-user token",
      "Content guardrails are attached only at the entry point",
      "The agent discloses secrets, its instructions or its tool surface",
    ],
    requires: [/^AGENT-GUARDRAIL-BYPASS$/],
    anyOf: [/^AGENT-HIERARCHY-/, /^AGENT-ACL-BYPASS$/],
    alsoAnyOf: [/^AGENT-(CREDENTIAL|SYSTEM-PROMPT|TOOL-SCHEMA)-LEAK$/],
    impact: "Unfiltered agent access can be used to extract credentials or internal instructions with no content policy applied.",
    blocker: true,
  },
  {
    id: "PATH-INJECTION-TO-AGENT-ACTION",
    name: "Prompt injection → excessive agency",
    steps: [
      "The agent follows instructions carried in untrusted content",
      "Sub-agent or entitlement boundaries are not independently enforced",
    ],
    requires: [/^AGENT-(DIRECT|INDIRECT)-INJECTION$/],
    anyOf: [/^AGENT-ACL-BYPASS$/, /^AGENT-HIERARCHY-/, /^AGENT-IDENTITY-SPOOF$/],
    impact: "Text supplied by a third party can steer the agent into actions the caller is not entitled to perform.",
    blocker: true,
  },
  {
    id: "PATH-XSS-TO-TOKEN-THEFT",
    name: "Unencoded output → token theft",
    steps: [
      "User input is reflected into HTML without encoding",
      "Authentication tokens are readable from web storage",
      "No restrictive CSP constrains injected script",
    ],
    requires: [/^INJECT-REFLECTED-XSS$/, /^WEB-TOKEN-STORAGE$/],
    anyOf: [/^WEB-HEADER-CONTENT-SECURITY-POLICY$/],
    impact: "A single crafted link can exfiltrate a victim's session token, because script runs and the token is script-readable.",
    blocker: true,
  },
  {
    id: "PATH-SESSION-PERSISTENCE",
    name: "Stolen token cannot be withdrawn",
    steps: ["Tokens remain valid after logout, or expiry is not enforced", "Token lifetime is unbounded or over-long"],
    requires: [/^SESSION-(LOGOUT|EXPIRED-TOKEN)$/],
    anyOf: [/^TOKEN-LIFETIME$/],
    impact: "A leaked credential stays usable and cannot be revoked, so containment after an incident is not possible.",
    blocker: true,
  },
  {
    id: "PATH-TRAVERSAL-TO-SECRETS",
    name: "File access → configuration secrets",
    steps: ["A file parameter escapes its base directory, or artefacts are served directly", "Deployment configuration is reachable"],
    requires: [/^INJECT-PATH-TRAVERSAL$/],
    anyOf: [/^WEB-EXPOSED-/, /^WEB-DIRECTORY-LISTING$/],
    impact: "Arbitrary file reads plus exposed configuration hand over credentials for downstream systems.",
    blocker: true,
  },
];

/**
 * Which paths are corroborated by this run's failures?
 * `failingIds` is the set of IDs whose status is "fail".
 */
export function matchAttackPaths(failingIds) {
  const ids = [...failingIds];
  const hits = (patterns) => ids.filter((id) => patterns.some((p) => p.test(id)));
  return ATTACK_PATHS.map((path) => {
    const required = (path.requires ?? []).map((p) => ids.filter((id) => p.test(id))).filter((m) => m.length);
    if (required.length !== (path.requires ?? []).length) return null;
    const any = path.anyOf ? hits(path.anyOf) : [];
    if (path.anyOf && any.length === 0) return null;
    const also = path.alsoAnyOf ? hits(path.alsoAnyOf) : [];
    if (path.alsoAnyOf && also.length === 0) return null;
    const evidence = [...new Set([...required.flat(), ...any, ...also])];
    return { ...path, evidence };
  }).filter(Boolean);
}

/** Collapse families of near-identical passing titles into one architectural statement. */
export const SUMMARY_RULES = [
  { pattern: /^Sensitive resource is not exposed/i, summary: "Sensitive deployment artefacts are not publicly exposed" },
  { pattern: /rejects direct external invocation/i, summary: "Direct access to sub-agents is blocked" },
  { pattern: /^Security header .* is deployed/i, summary: "Browser security headers are deployed" },
  { pattern: /resists .*injection/i, summary: "Agent resists prompt injection across input channels" },
];
