/**
 * ====================================================================
 *  JIRA: PLATFORM-2850 — Fix JWT Token Expiry Bypass Vulnerability
 * ====================================================================
 *  Priority: P0 — Security | Sprint: Sprint 24 | Points: 2
 *  Reporter: Security Team (automated scan)
 *  Assignee: You (Intern)
 *  Due: ASAP — active exploitation detected
 *  Labels: security, auth, jwt, critical
 *
 *  DESCRIPTION:
 *  Security audit found that expired JWT tokens are still accepted by
 *  our auth middleware. The `exp` claim is present in tokens but the
 *  middleware never checks it. Additionally, revoked tokens (e.g.,
 *  after password change or logout) are still valid because there's
 *  no token blacklist check.
 *
 *  SECURITY AUDIT LOG:
 *  ───────────────────
 *  [VULN-HIGH] Token with exp=1707580800 (Feb 10) accepted on Feb 14
 *  [VULN-HIGH] Revoked token for user_42 still grants API access
 *  [VULN-MED]  Token signature not verified against correct algorithm
 *  [INFO] 23 expired tokens used in last 24 hours
 *
 *  SLACK THREAD — #security-incidents — Feb 14:
 *  ─────────────────────────────────────────────
 *  @security-bot 8:00 AM:
 *    "🚨 SECURITY ALERT: Expired JWT tokens being accepted. 23
 *     expired tokens used for API access in last 24h."
 *  @chen.wei (Security Lead) 8:05 AM:
 *    "The middleware checks the signature but never validates `exp`.
 *     Also there's no blacklist check for revoked tokens."
 *  @nisha.gupta (Tech Lead) 8:10 AM:
 *    "@intern — Fix authMiddleware.ts. Three bugs:
 *     1. Add expiry check (compare exp claim against Date.now())
 *     2. Add blacklist check for revoked tokens
 *     3. The algorithm should be 'HS256', not 'none'"
 *
 *  ACCEPTANCE CRITERIA:
 *  - [ ] Expired tokens return 401 with "Token expired" message
 *  - [ ] Revoked tokens return 401 with "Token revoked" message
 *  - [ ] Algorithm is enforced as HS256 (reject 'none' algorithm)
 *  - [ ] Valid, non-expired, non-revoked tokens pass through
 *  - [ ] All test cases at bottom pass
 * ====================================================================
 */

import * as crypto from 'crypto';

const JWT_SECRET = 'super-secret-key-2026';

// Simulated token blacklist (in production, this would be Redis)
const revokedTokens: Set<string> = new Set([
    'revoked-token-user42-abc123',
    'revoked-token-user15-def456',
]);

interface JWTPayload {
    sub: string;
    email: string;
    role: string;
    iat: number;
    exp: number;
    jti: string;  // JWT ID for blacklist lookup
}

function base64UrlDecode(str: string): string {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(str, 'base64').toString('utf-8');
}

function verifySignature(token: string, secret: string): boolean {
    const parts = token.split('.');
    if (parts.length !== 3) return false;

    const header = JSON.parse(base64UrlDecode(parts[0]));

    // BUG: Accepts algorithm "none" which means no signature verification
    // An attacker can set alg: "none" and forge any token
    if (header.alg === 'none') return true;

    const signature = crypto
        .createHmac('sha256', secret)
        .update(`${parts[0]}.${parts[1]}`)
        .digest('base64url');

    return signature === parts[2];
}

function decodePayload(token: string): JWTPayload {
    const parts = token.split('.');
    return JSON.parse(base64UrlDecode(parts[1]));
}

/**
 * Authentication middleware — verifies JWT token from Authorization header.
 */
function authMiddleware(req: any, res: any, next: () => void): void {
    const authHeader = req.headers?.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ error: 'Missing authorization header' });
        return;
    }

    const token = authHeader.substring(7);

    // Step 1: Verify signature
    if (!verifySignature(token, JWT_SECRET)) {
        res.status(401).json({ error: 'Invalid token signature' });
        return;
    }

    // Step 2: Decode payload
    const payload = decodePayload(token);

    // BUG: Missing expiry check!
    // Should verify: payload.exp > Math.floor(Date.now() / 1000)
    // Without this, expired tokens are accepted forever

    // BUG: Missing blacklist check!
    // Should verify: !revokedTokens.has(payload.jti)
    // Without this, logged-out users can still use old tokens

    // Attach user to request
    req.user = {
        id: payload.sub,
        email: payload.email,
        role: payload.role
    };

    next();
}

export { authMiddleware, verifySignature, decodePayload, revokedTokens };

/* =====================================================================
 *  TEST CASES — Verify your fix
 * =====================================================================
 *
 *  // TEST 1: Valid token should pass
 *  // Create a token with exp = future, valid signature → next() called
 *
 *  // TEST 2: Expired token should fail
 *  // Token with exp = 1707580800 (past) → 401 "Token expired"
 *
 *  // TEST 3: Revoked token should fail
 *  // Token with jti = "revoked-token-user42-abc123" → 401 "Token revoked"
 *
 *  // TEST 4: Algorithm "none" should be rejected
 *  // Token with alg: "none" → 401 "Invalid token"
 *
 *  // TEST 5: Missing auth header → 401
 *
 * =====================================================================
 */
