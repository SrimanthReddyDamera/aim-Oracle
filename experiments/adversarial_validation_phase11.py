"""
BRICK 4.2-S PHASE 1.1: POST-REMEDIATION ADVERSARIAL VALIDATION HARNESS
=====================================================================
Verification-only attack suite testing variants against the Phase 1 remediation.
Covers:
1. Entity substitution variants (CamelCase, hyphenated, versioned, lowercase, proper nouns, scope)
2. Negation / polarity reversal variants (grammatical, suffix, prepositions, antonyms, exclusionary)
3. Compound proposition variants (coordinating, subordinating, punctuation, colons, dashes, 'also', 'with')
4. Numerical compound attacks & citation bracket handling
5. False-positive validation on legitimate claims
"""

import sys
from pathlib import Path
from typing import List, Dict, Any

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.evidence.models import Evidence
from backend.synthesis.models import Claim
from backend.synthesis.entailment import EntailmentVerifier


def _ev(ev_id: str, content: str) -> Evidence:
    return Evidence(
        evidence_id=ev_id,
        source_id="DOC-SRC",
        source_type="document",
        uri="file:///doc.md",
        content=content,
        content_hash="h123",
        source_path="/doc.md",
        chunk_index=0,
        start_offset=0,
        end_offset=len(content),
        metadata={},
        created_at="2026-09-01T00:00:00Z",
    )


def run_all_attacks():
    results: List[Dict[str, Any]] = []

    def test_case(cat: str, name: str, ev_text: str, claim_stmt: str, anchor: str = None, should_pass: bool = False):
        ev = _ev("EV-TEST", ev_text)
        claim = Claim(claim_id=f"c_{len(results)+1}", statement=claim_stmt, evidence_ids=["EV-TEST"], verbatim_anchor=anchor)
        is_entailed, reason = EntailmentVerifier.verify_claim_entailment(claim, ev)

        if should_pass:
            if is_entailed:
                status = "PASS"
                classification = "PASS"
            else:
                status = "FAIL"
                classification = "FALSE POSITIVE"
        else:
            if not is_entailed:
                status = "PASS"
                classification = "BLOCKED"
            else:
                status = "FAIL"
                classification = "BYPASS"

        results.append({
            "id": len(results) + 1,
            "category": cat,
            "name": name,
            "ev": ev_text,
            "claim": claim_stmt,
            "anchor": anchor,
            "should_pass": should_pass,
            "is_entailed": is_entailed,
            "reason": reason,
            "classification": classification,
            "status": status,
        })

    # =========================================================================
    # 1. ENTITY SUBSTITUTION ATTACKS (Expected: BLOCKED)
    # =========================================================================
    # A. CamelCase
    test_case("Entity", "CamelCase Substitution", "ServiceA failed during cutover.", "ServiceB failed during cutover.")
    # B. Hyphenated
    test_case("Entity", "Hyphenated Entity Substitution", "auth-gateway handles traffic.", "billing-gateway handles traffic.")
    # C. Underscore
    test_case("Entity", "Underscore Entity Substitution", "worker_pool_1 is healthy.", "worker_pool_2 is healthy.")
    # D. Versioned
    test_case("Entity", "Versioned Entity Substitution", "Redis-v5 is operational.", "Redis-v6 is operational.")
    # E. Proper Noun
    test_case("Entity", "Proper Noun City Substitution", "Tokyo handles external traffic.", "Singapore handles external traffic.")
    # F. Normal Noun Phrase (scope / environment)
    test_case("Entity", "Noun Phrase Scope Substitution", "The production cluster failed.", "The staging cluster failed.")
    # G. Adjective + Noun
    test_case("Entity", "Adjective+Noun Component Substitution", "The primary database failed.", "The secondary database failed.")
    # H. Capitalized Multi-word Component
    test_case("Entity", "Multiword Component Substitution", "Payment Gateway failed.", "Authentication Gateway failed.")
    # I. Lowercase Unmatched Material Token in Short Proposition
    test_case("Entity", "Single Predicate Material Substitution", "ServiceA failed during cutover.", "ServiceA failed during deployment.")
    # J. Entity Appears in Claim Only
    test_case("Entity", "Foreign Entity Appears in Claim", "Core service restarted at midnight.", "Kafka service restarted at midnight.")
    # K. Cross-attributing Entity to Different State
    test_case("Entity", "Cross-Entity Metric Swapping", "ClusterA has 10 nodes. ClusterB has 50 nodes.", "ClusterA has 50 nodes.")

    # =========================================================================
    # 2. NEGATION / POLARITY & EXCLUSION ATTACKS (Expected: BLOCKED)
    # =========================================================================
    # A. Suffix negation drop (Singapore, not Tokyo)
    test_case("Negation", "Suffix Negation Target Drop", "The gateway routes through Singapore, not Tokyo.", "The gateway routes through Tokyo.", anchor="routes through")
    # B. 'never' prefix negation affirmed
    test_case("Negation", "Never Verb Negation Reversal", "The service never connects to Database B.", "The service connects to Database B.")
    # C. 'does not' verb negation affirmed
    test_case("Negation", "Does Not Verb Negation Reversal", "The proxy does not send traffic to Region X.", "The proxy sends traffic to Region X.")
    # D. 'without' negation affirmed
    test_case("Negation", "Without Negation Reversal", "The cluster operates without automated failover.", "The cluster operates with automated failover.")
    # E. 'cannot' negation affirmed
    test_case("Negation", "Cannot Verb Negation Reversal", "The client cannot authenticate to LDAP.", "The client can authenticate to LDAP.")
    # F. 'can't' contraction negation affirmed
    test_case("Negation", "Cant Contraction Negation Reversal", "The server cant accept unencrypted requests.", "The server can accept unencrypted requests.")
    # G. 'is not' state negation affirmed
    test_case("Negation", "Is Not State Negation Reversal", "The service is not active in US-West.", "The service is active in US-West.")
    # H. 'was not' historical state affirmed
    test_case("Negation", "Was Not State Negation Reversal", "The patch was not deployed to production.", "The patch was deployed to production.")
    # I. 'rather than' exclusion affirmed
    test_case("Negation", "Rather Than Negation Reversal", "The gateway routes through Singapore rather than Tokyo.", "The gateway routes through Tokyo.", anchor="routes through")
    # J. 'instead of' exclusion affirmed
    test_case("Negation", "Instead Of Negation Reversal", "The gateway routes through Singapore instead of Tokyo.", "The gateway routes through Tokyo.", anchor="routes through")
    # K. 'disabled' state affirmed as enabled/running
    test_case("Negation", "Disabled State Inversion", "Automated failover is disabled.", "Automated failover is running.")
    # L. 'rejected' state affirmed as approved
    test_case("Negation", "Rejected State Inversion", "Change request CR-100 was rejected.", "Change request CR-100 is approved.")
    # M. Antonym opposition (vulnerable vs secure)
    test_case("Negation", "Antonym Contradiction (Secure vs Vulnerable)", "The core service is vulnerable to RCE.", "The core service is secure against RCE.")
    # N. Antonym opposition (offline vs online)
    test_case("Negation", "Antonym Contradiction (Online vs Offline)", "Host Alpha is offline.", "Host Alpha is online.")
    # O. 'as opposed to' exclusion affirmed
    test_case("Negation", "As Opposed To Exclusion Reversal", "The gateway routes through Singapore as opposed to Tokyo.", "The gateway routes through Tokyo.", anchor="routes through")
    # P. 'in preference to' exclusion affirmed
    test_case("Negation", "In Preference To Exclusion Reversal", "The gateway routes through Singapore in preference to Tokyo.", "The gateway routes through Tokyo.", anchor="routes through")
    # Q. 'excluding' exclusion affirmed
    test_case("Negation", "Excluding Exclusion Reversal", "The gateway handles all regions excluding Tokyo.", "The gateway handles Tokyo.")
    # R. 'except for' exclusion affirmed
    test_case("Negation", "Except For Exclusion Reversal", "The gateway routes to all nodes except for NodeB.", "The gateway routes to NodeB.")
    # S. 'other than' exclusion affirmed
    test_case("Negation", "Other Than Exclusion Reversal", "The system allows connections other than Port80.", "The system allows connections to Port80.")
    # T. 'avoids' exclusion affirmed
    test_case("Negation", "Avoids Exclusion Reversal", "The proxy avoids Tokyo.", "The proxy connects to Tokyo.")
    # U. 'avoiding' exclusion affirmed
    test_case("Negation", "Avoiding Exclusion Reversal", "The proxy routes traffic avoiding Tokyo.", "The proxy routes traffic to Tokyo.")

    # =========================================================================
    # 3. COMPOUND CLAIM ATTACKS (Expected: BLOCKED)
    # =========================================================================
    test_case("Compound", "Joined by 'and'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second and authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by 'but'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second but authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by 'however'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second, however authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by 'yet'", "Database replication is enabled.", "Database replication is enabled, yet automated failover is completely broken.", anchor="Database replication is enabled")
    test_case("Compound", "Joined by 'because'", "Region A is active.", "Region A is active because Region B completely collapsed.", anchor="Region A is active")
    test_case("Compound", "Joined by 'since'", "Region A is active.", "Region A is active since Region B completely collapsed.", anchor="Region A is active")
    test_case("Compound", "Joined by 'moreover'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second, moreover authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by 'furthermore'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second, furthermore authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by 'plus'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second, plus authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by 'while'", "Database replication is enabled.", "Database replication is enabled while automated failover is completely broken.", anchor="Database replication is enabled")
    test_case("Compound", "Joined by 'whereas'", "Region A is active.", "Region A is active whereas Region B is completely broken.", anchor="Region A is active")
    test_case("Compound", "Joined by 'although'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second although authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by semicolon ';'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second; authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by full sentence boundary", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second. Authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by 'also'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second, also authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by colon ':'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second: authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by em-dash '—'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second \u2014 authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by en-dash '–'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second \u2013 authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by double hyphen '--'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second -- authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by comma splice ','", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second, authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by 'with'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second with authentication completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by 'therefore'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second, therefore authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by 'nevertheless'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second, nevertheless authentication is completely broken.", anchor="API gateway handles 500 requests per second")
    test_case("Compound", "Joined by 'despite'", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second despite authentication being completely broken.", anchor="API gateway handles 500 requests per second")

    # =========================================================================
    # 4. NUMERICAL COMPOUND & CITATION ATTACKS (Expected: BLOCKED)
    # =========================================================================
    test_case("Numerical", "Appended unsupported number via 'and'", "We deployed 10 instances.", "We deployed 10 instances and 20 are reserved.")
    test_case("Numerical", "Appended unsupported number via 'however'", "We deployed 10 instances.", "We deployed 10 instances, however 20 are reserved.")
    test_case("Numerical", "Appended unsupported number via em-dash", "We deployed 10 instances.", "We deployed 10 instances \u2014 20 are reserved.")
    test_case("Numerical", "Appended unsupported number via 'with'", "We deployed 10 instances.", "We deployed 10 instances with 20 additional instances.")
    test_case("Numerical", "Altered metric in statement", "We deployed 10 instances.", "We deployed 20 instances.")
    test_case("Numerical", "Citation bracket number spoofing [20]", "We deployed 10 instances.", "We deployed [20] instances.")
    test_case("Numerical", "Citation bracket port spoofing [9090]", "We deployed 10 instances.", "Listening on port [9090].")
    test_case("Numerical", "Citation bracket metric spoofing [999]", "We deployed 10 instances.", "Latency is [999] ms.")
    test_case("Numerical", "Out of range citation index at end [20]", "We deployed 10 instances.", "We deployed 10 instances [20].")
    test_case("Numerical", "Out of range citation index at end [999]", "We deployed 10 instances.", "We deployed 10 instances [999].")

    # =========================================================================
    # 5. FALSE-POSITIVE ATTACKS ON LEGITIMATE CLAIMS (Expected: ACCEPTED)
    # =========================================================================
    test_case("Legitimate", "Parenthetical non-clause comma", "The service, deployed in March, handles 500 rps.", "The service, deployed in March, handles 500 rps.", should_pass=True)
    test_case("Legitimate", "Grounded compound statement with 'and'", "The gateway handles 500 rps and routes through Singapore.", "The gateway handles 500 rps and routes through Singapore.", should_pass=True)
    test_case("Legitimate", "Grounded negative statement preserved", "The gateway does not route through Tokyo.", "The gateway does not route through Tokyo.", should_pass=True)
    test_case("Legitimate", "Grounded single clause statement", "The API gateway handles 500 requests per second.", "The API gateway handles 500 requests per second.", should_pass=True)
    test_case("Legitimate", "Grounded affirmative target after anchor", "The payment gateway routes transactions through Singapore.", "The payment gateway routes transactions through Singapore.", anchor="routes transactions through", should_pass=True)
    test_case("Legitimate", "Grounded statement with reporting prefix", "System is online.", "Verified from DOC-SRC: System is online.", anchor="System is online.", should_pass=True)
    test_case("Legitimate", "Grounded statement citing document offset citation", "Host is operational.", "Host is operational [1].", should_pass=True)
    test_case("Legitimate", "Grounded selected target under 'rather than'", "The gateway routes through Singapore rather than Tokyo.", "The gateway routes through Singapore.", anchor="routes through", should_pass=True)
    test_case("Legitimate", "Grounded selected target under 'instead of'", "The gateway routes through Singapore instead of Tokyo.", "The gateway routes through Singapore.", anchor="routes through", should_pass=True)
    test_case("Legitimate", "Grounded bracketed number matching evidence", "We deployed 20 instances.", "We deployed [20] instances.", should_pass=True)
    test_case("Legitimate", "Grounded number with valid citation marker", "We deployed 10 instances.", "We deployed 10 instances [1].", should_pass=True)
    test_case("Legitimate", "Grounded parenthetical relative clause", "The service, which was deployed in March, handles 500 rps.", "The service, which was deployed in March, handles 500 rps.", should_pass=True)

    return results


if __name__ == "__main__":
    results = run_all_attacks()
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")

    bypasses = [r for r in results if r["classification"] == "BYPASS"]
    fps = [r for r in results if r["classification"] == "FALSE POSITIVE"]
    blocked = [r for r in results if r["classification"] == "BLOCKED"]
    legit_passes = [r for r in results if r["classification"] == "PASS"]

    print("=" * 80)
    print(f"PHASE 1.1 ADVERSARIAL VALIDATION RESULTS: {passed}/{total} PASSED")
    print("=" * 80)
    print(f"Total attacks/cases: {total}")
    print(f"Adversarial Attacks Blocked: {len(blocked)}")
    print(f"Legitimate Claims Accepted:  {len(legit_passes)}")
    print(f"Bypasses Discovered:        {len(bypasses)}")
    print(f"False Positives Discovered:  {len(fps)}")
    print("-" * 80)

    for r in results:
        mark = "PASS" if r["status"] == "PASS" else "FAIL"
        print(f"[{mark:^4}] #{r['id']:02d} | Cat: {r['category']:<10} | Class: {r['classification']:<15} | {r['name']}")
        if r["status"] == "FAIL":
            print(f"    FAILURE DETAIL: is_entailed={r['is_entailed']}, reason={r['reason']}")
            print(f"    Ev:    '{r['ev']}'")
            print(f"    Claim: '{r['claim']}'")

    sys.exit(0 if failed == 0 else 1)
