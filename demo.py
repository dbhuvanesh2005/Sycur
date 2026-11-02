from collections import Counter
from datetime import datetime
from pathlib import Path
import shutil
import time
import uuid

from sycur_rag.correlation import correlate_findings
from sycur_rag.evidence.balancer import balance_evidence_layers
from sycur_rag.evidence.builder import build_evidence_candidates
from sycur_rag.evidence.knapsack import select_evidence
from sycur_rag.evidence.pack import build_evidence_pack
from sycur_rag.llm import generate_grounded_explanation
from sycur_rag.policy_engine import (
    PolicyInput,
    aggregate_review_decisions,
    decide_finding_policy,
)
from sycur_rag.retrieval.hybrid import search_hybrid
from sycur_rag.scanners.bandit import BanditAdapter
from sycur_rag.scanners.checkov import CheckovAdapter
from sycur_rag.scanners.gitleaks import GitleaksAdapter
from sycur_rag.scanners.orchestrator import ScannerOrchestrator
from sycur_rag.scanners.osv import OSVScannerAdapter
from sycur_rag.scanners.semgrep import SemgrepAdapter
from sycur_rag.scanners.trivy import TrivyAdapter


ROOT = Path(__file__).resolve().parent.parent
DEMO_REPO = ROOT / "demo" / "sample_pr"


adapters = {
    "gitleaks": GitleaksAdapter(
        executable=str(
            ROOT / "tools/gitleaks/v8.30.0/gitleaks"
        ),
        repository_root=DEMO_REPO,
    ),

    "semgrep": SemgrepAdapter(
        executable=shutil.which("semgrep"),
        config=str(
            ROOT / "demo/semgrep-rule.yml"
        ),
        repository_root=DEMO_REPO,
    ),

    "bandit": BanditAdapter(
        executable=shutil.which("bandit"),
        repository_root=DEMO_REPO,
    ),

    "trivy": TrivyAdapter(
        executable=shutil.which("trivy"),
        repository_root=DEMO_REPO,
    ),

    "osv": OSVScannerAdapter(
        executable=shutil.which("osv-scanner"),
        repository_root=DEMO_REPO,
    ),

    "checkov": CheckovAdapter(
        executable=shutil.which("checkov"),
        repository_root=DEMO_REPO,
    ),
}


orchestrator = ScannerOrchestrator(
    repository_root=DEMO_REPO,
    adapters=adapters,
)


changed_files = [
    # Python
    "app.py",

    # React / TypeScript
    "react/Login.tsx",

    # Flutter / Dart
    "flutter/login_screen.dart",

    # Java
    "java/UserController.java",

    # Spring Boot
    "spring/AuthController.java",

    # Secrets
    "secret.txt",

    # Infrastructure
    "main.tf",

    # Python dependencies
    "requirements.txt",

    # Node dependencies
    "package-lock.json",

    # Maven dependencies
    "pom.xml",
]


# ============================================================
# START REVIEW
# ============================================================

review_id = str(
    uuid.uuid4()
)

reviewed_at = (
    datetime.now()
    .astimezone()
)

start_time = (
    time.perf_counter()
)


print()
print("🚀 SYCUR review started...")


# ============================================================
# SCANNERS
# ============================================================

result = orchestrator.run(
    changed_files
)


# ============================================================
# CORRELATION
# ============================================================

correlated_findings = (
    correlate_findings(
        list(result.findings)
    )
)


# ============================================================
# POLICY
# ============================================================

policy_decisions = []

for group in correlated_findings:

    requires_evidence = any(
        finding.requires_evidence
        for finding in group.findings
    )

    decision = decide_finding_policy(
        PolicyInput(
            severity=group.severity,
            finding_present=True,
            evidence_sufficient=(
                not requires_evidence
            ),
            requires_evidence=(
                requires_evidence
            ),
            rule_id=(
                group.primary.rule_id
            ),
        )
    )

    policy_decisions.append(
        decision
    )


final_decision = (
    aggregate_review_decisions(
        policy_decisions
    )
)


# ============================================================
# RAG + QWEN
#
# Detailed explanation for the correlated CWE-78 issue.
# We do not print/explain all 50 findings in this terminal demo.
# ============================================================

command_injection_group = next(
    (
        group
        for group in correlated_findings
        if "CWE-78" in group.cwe_ids
        and "semgrep" in group.scanners
        and "bandit" in group.scanners
    ),
    None,
)


explanation = None
evidence_pack = None


if command_injection_group is not None:

    primary = (
        command_injection_group.primary
    )

    query_text = (
        f"{primary.title}. "
        f"{primary.message}. "
        "Explain the security risk and "
        "recommended remediation."
    )

    rag_results = search_hybrid(
        query_text=query_text,
        cwe_ids=list(
            command_injection_group.cwe_ids
        ),
        scanner=primary.scanner,
        rule_id=primary.rule_id,
        file_path=primary.file_path,
        preferred_layers=[
            "weakness_taxonomy",
            "remediation",
            "requirements",
            "testing",
        ],
    )

    if rag_results:

        candidates = (
            build_evidence_candidates(
                rag_results
            )
        )

        balanced = (
            balance_evidence_layers(
                candidates,
                max_candidates=len(
                    candidates
                ),
                preferred_layers=[
                    "weakness_taxonomy",
                    "remediation",
                    "requirements",
                    "testing",
                ],
            )
        )

        selection = select_evidence(
            balanced
        )

        evidence_pack = (
            build_evidence_pack(
                query_text=query_text,
                selection=selection,
            )
        )

        if evidence_pack.has_evidence:

            explanation = (
                generate_grounded_explanation(
                    question=query_text,
                    evidence=evidence_pack,
                )
            )


# ============================================================
# SUMMARY DATA
# ============================================================

severity_counts = Counter(
    group.severity.value
    for group in correlated_findings
)


scanners_used = sorted(
    {
        finding.scanner
        for finding in result.findings
    }
)


blocking_count = sum(
    1
    for decision in policy_decisions
    if decision.action.value
    == "BLOCK"
)


duration = (
    time.perf_counter()
    - start_time
)


# ============================================================
# CLEAN SYCUR REPORT
# ============================================================

print()
print("=" * 64)
print("              SYCUR PR SECURITY REVIEW")
print("=" * 64)

print()
print("Repository           : demo/sample_pr")
print("Pull Request         : LOCAL-DEMO")
print(
    "Reviewed At         :",
    reviewed_at.isoformat(
        timespec="seconds"
    ),
)
print(
    "Scan Duration       :",
    f"{duration:.2f}s",
)
print(
    "Review ID           :",
    review_id,
)


print()
print("-" * 64)
print("SCAN SUMMARY")
print("-" * 64)

print(
    "Scanners            :",
    f"{len(scanners_used)}/6",
)

print(
    "Scanner Names       :",
    ", ".join(
        scanners_used
    ),
)

print(
    "Changed Files       :",
    len(changed_files),
)

print(
    "Raw Findings        :",
    len(result.findings),
)

print(
    "Correlated Findings :",
    len(correlated_findings),
)


print()
print("-" * 64)
print("RISK SNAPSHOT")
print("-" * 64)

print(
    "Critical            :",
    severity_counts.get(
        "CRITICAL",
        0,
    ),
)

print(
    "High                :",
    severity_counts.get(
        "HIGH",
        0,
    ),
)

print(
    "Medium              :",
    severity_counts.get(
        "MEDIUM",
        0,
    ),
)

print(
    "Low                 :",
    severity_counts.get(
        "LOW",
        0,
    ),
)


print()
print("-" * 64)
print("FINAL DECISION")
print("-" * 64)

print(
    "Status              :",
    final_decision.status.value,
)

print(
    "Merge Decision      :",
    final_decision.action.value,
)

print(
    "Highest Risk        :",
    final_decision.severity.value,
)

print(
    "Blocking Findings   :",
    blocking_count,
)

print(
    "Policy Reason       :",
    final_decision.reason,
)


stack_files = [
    ("Python", "app.py"),
    ("React / TypeScript", "react/Login.tsx"),
    ("Flutter / Dart", "flutter/login_screen.dart"),
    ("Java", "java/UserController.java"),
    ("Spring Boot", "spring/AuthController.java"),
    ("Terraform", "main.tf"),
    ("Secrets", "secret.txt"),
    ("Python Dependency", "requirements.txt"),
    ("Node Dependency", "package-lock.json"),
    ("Maven Dependency", "pom.xml"),
]

print()
print("-" * 64)
print("STACK / LANGUAGE COVERAGE")
print("-" * 64)

for stack_name, file_path in stack_files:
    count = sum(
        1
        for finding in result.findings
        if finding.file_path == file_path
    )
    print(f"{stack_name:<22} {file_path:<27} {count}")


# ============================================================
# ALL UNIQUE SECURITY FINDINGS — GROUPED BY FILE
# ============================================================
severity_priority = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "N/A": 0,
}

print()
print("-" * 64)
print("ALL SECURITY FINDINGS — GROUPED BY FILE")
print("-" * 64)

for file_path in changed_files:
    file_groups = [
        group
        for group in correlated_findings
        if group.primary.file_path == file_path
    ]

    if not file_groups:
        continue

    file_groups = sorted(
        file_groups,
        key=lambda group: (
            -severity_priority[group.severity.value],
            group.primary.line_start or 0,
            group.primary.title,
        ),
    )

    print()
    print("=" * 64)
    print(f"FILE: {file_path}")
    print(f"UNIQUE SECURITY ISSUES: {len(file_groups)}")
    print("=" * 64)

    for index, group in enumerate(file_groups, start=1):
        primary = group.primary
        rule_ids = tuple(
            dict.fromkeys(
                finding.rule_id
                for finding in group.findings
            )
        )

        location = file_path

        if primary.line_start is not None:
            location += f":{primary.line_start}"

            if (
                primary.line_end is not None
                and primary.line_end != primary.line_start
            ):
                location += f"-{primary.line_end}"

        print()
        print(
            f"[{index}] {group.severity.value} "
            f"— {primary.title}"
        )
        print("Location        :", location)
        print(
            "Detected By     :",
            " + ".join(
                scanner.capitalize()
                for scanner in group.scanners
            ),
        )
        print("Rule            :", ", ".join(rule_ids))

        if group.cwe_ids:
            print("CWE             :", ", ".join(group.cwe_ids))

        print("Main Error      :", primary.title)
        print("Security Reason :", primary.message)

        if group.severity.value in {"CRITICAL", "HIGH"}:
            print("Required Action : FIX BEFORE MERGE")
        else:
            print("Required Action : REVIEW AND REMEDIATE")


# ============================================================
# DETAILED RAG / AI FINDING
# ============================================================

if (
    command_injection_group
    is not None
    and explanation
    is not None
    and evidence_pack
    is not None
):

    print()
    print("-" * 64)
    print("GROUNDING EXAMPLE — SHELL COMMAND INJECTION")
    print("-" * 64)

    print()
    print(
        "Finding             :",
        command_injection_group
        .primary
        .title,
    )

    print(
        "Detected By         :",
        " + ".join(
            scanner.capitalize()
            for scanner
            in command_injection_group.scanners
        ),
    )

    print(
        "CWE                 :",
        ", ".join(
            command_injection_group.cwe_ids
        ),
    )


    print()
    print("RAG EVIDENCE")

    cited_sources = {
        source.source_id: source
        for source
        in evidence_pack.sources
    }

    for source_id in (
        explanation.source_ids
    ):

        source = cited_sources.get(
            source_id
        )

        if source is None:
            continue

        print(
            f"  [{source_id}] "
            f"{source.title} "
            f"({source.document_name})"
        )


    print()
    print("AI EXPLANATION")

    print(
        "  Summary :",
        explanation.finding_summary,
    )

    print(
        "  Risk    :",
        explanation.risk_explanation,
    )

    print(
        "  Fix     :",
        explanation.required_action,
    )

    print(
        "  Grounded:",
        explanation.evidence_sufficient,
    )


print()
print("-" * 64)
print("MERGE DECISION")
print("-" * 64)

print(
    final_decision.action.value
)

print(
    final_decision.reason
)

print()
print("=" * 64)
print(
    f"SYCUR review completed in "
    f"{duration:.2f}s"
)
print("=" * 64)
