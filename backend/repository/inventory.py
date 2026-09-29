"""
Repository Inventory Scanner (ORACLE 5.0 - Step 3)

Deterministically inspects a repository to construct a structured inventory:
- Languages, frameworks, runtimes, package managers
- Dependency manifests, source directories, test directories
- Docker and CI configurations, Git metadata and recent commit summaries
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.repository.adapter import RepositoryAdapter

logger = logging.getLogger("oracle.repository.inventory")


class RepositoryInventory(BaseModel):
    """Normalized structured inventory of an inspected codebase."""
    repository_name: str
    root_path: str
    languages: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    test_frameworks: List[str] = Field(default_factory=list)
    package_managers: List[str] = Field(default_factory=list)
    dependency_manifests: List[str] = Field(default_factory=list)
    source_directories: List[str] = Field(default_factory=list)
    test_directories: List[str] = Field(default_factory=list)
    configuration_files: List[str] = Field(default_factory=list)
    docker_files: List[str] = Field(default_factory=list)
    ci_configurations: List[str] = Field(default_factory=list)
    file_counts_by_extension: Dict[str, int] = Field(default_factory=dict)
    total_files: int = 0
    git_metadata: Dict[str, Any] = Field(default_factory=dict)
    recent_commits: List[Dict[str, Any]] = Field(default_factory=list)


class RepositoryInventoryScanner:
    """
    Constructs deterministic RepositoryInventory from a RepositoryAdapter.
    Does NOT send full source code to LLMs; constructs structured evidence first.
    """

    SUPPORTED_EXTENSIONS = [
        ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".rb",
        ".json", ".yaml", ".yml", ".toml", ".xml", ".sql", ".sh", ".dockerfile", ".txt"
    ]

    FRAMEWORK_SIGNATURES = {
        "FastAPI": ["fastapi", "from fastapi import"],
        "Flask": ["flask", "from flask import"],
        "Django": ["django", "django.conf"],
        "Express": ["express", "require('express')"],
        "Next.js": ["next", "next/navigation"],
        "Spring Boot": ["org.springframework.boot"],
        "Gin": ["github.com/gin-gonic/gin"],
    }

    TEST_FRAMEWORK_SIGNATURES = {
        "pytest": ["pytest", "def test_"],
        "unittest": ["unittest", "TestCase"],
        "jest": ["jest", "describe(", "it("],
        "go test": ["testing.T"],
    }

    def __init__(self, adapter: RepositoryAdapter):
        self.adapter = adapter

    def scan(self) -> RepositoryInventory:
        all_files = self.adapter.list_files(extensions=self.SUPPORTED_EXTENSIONS, max_files=1000)
        ext_counts: Dict[str, int] = {}
        for f in all_files:
            ext = Path(f).suffix.lower() or Path(f).name.lower()
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

        languages = self._detect_languages(ext_counts)
        manifests = self._detect_manifests(all_files)
        pkg_managers = self._detect_package_managers(manifests)
        src_dirs, test_dirs = self._detect_directories(all_files)
        config_files, docker_files, ci_files = self._detect_config_and_ci(all_files)
        frameworks, test_frameworks = self._detect_frameworks(all_files, manifests)

        git_meta = self.adapter.get_repository_metadata()
        recent_commits = self.adapter.get_recent_commits(limit=5)

        return RepositoryInventory(
            repository_name=git_meta.get("name", "repository"),
            root_path=git_meta.get("root_path", ""),
            languages=languages,
            frameworks=frameworks,
            test_frameworks=test_frameworks,
            package_managers=pkg_managers,
            dependency_manifests=manifests,
            source_directories=src_dirs,
            test_directories=test_dirs,
            configuration_files=config_files,
            docker_files=docker_files,
            ci_configurations=ci_files,
            file_counts_by_extension=ext_counts,
            total_files=len(all_files),
            git_metadata=git_meta,
            recent_commits=recent_commits,
        )

    def _detect_languages(self, ext_counts: Dict[str, int]) -> List[str]:
        mapping = {
            ".py": "Python",
            ".ts": "TypeScript",
            ".tsx": "TypeScript (React)",
            ".js": "JavaScript",
            ".jsx": "JavaScript (React)",
            ".go": "Go",
            ".java": "Java",
            ".rs": "Rust",
            ".rb": "Ruby",
        }
        detected = []
        for ext, lang in mapping.items():
            if ext_counts.get(ext, 0) > 0 and lang not in detected:
                detected.append(lang)
        return detected or ["Unknown"]

    def _detect_manifests(self, files: List[str]) -> List[str]:
        known = {
            "requirements.txt", "pyproject.toml", "setup.py", "Pipfile",
            "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
            "go.mod", "go.sum", "Cargo.toml", "pom.xml", "build.gradle"
        }
        return [f for f in files if Path(f).name in known]

    def _detect_package_managers(self, manifests: List[str]) -> List[str]:
        names = {Path(m).name for m in manifests}
        res = []
        if "pyproject.toml" in names or "poetry.lock" in names:
            res.append("poetry")
        if "requirements.txt" in names or "setup.py" in names:
            res.append("pip")
        if "package-lock.json" in names:
            res.append("npm")
        if "yarn.lock" in names:
            res.append("yarn")
        if "pnpm-lock.yaml" in names:
            res.append("pnpm")
        if "go.mod" in names:
            res.append("go modules")
        if "Cargo.toml" in names:
            res.append("cargo")
        return res

    def _detect_directories(self, files: List[str]) -> tuple[List[str], List[str]]:
        src_candidates = {"src", "app", "lib", "pkg", "internal", "backend", "frontend"}
        test_candidates = {"test", "tests", "spec", "specs", "__tests__"}

        found_src = set()
        found_test = set()
        for f in files:
            parts = Path(f).parts
            if len(parts) > 1:
                first = parts[0].lower()
                if first in src_candidates:
                    found_src.add(parts[0])
                elif first in test_candidates:
                    found_test.add(parts[0])

        return sorted(list(found_src)), sorted(list(found_test))

    def _detect_config_and_ci(self, files: List[str]) -> tuple[List[str], List[str], List[str]]:
        configs = []
        dockers = []
        ci = []

        for f in files:
            f_lower = f.lower()
            name = Path(f).name.lower()
            if "dockerfile" in name or name.startswith("docker-compose"):
                dockers.append(f)
            elif ".github/workflows" in f_lower or "gitlab-ci" in f_lower or "jenkinsfile" in f_lower:
                ci.append(f)
            elif name in {
                "tsconfig.json", ".env.example", "settings.py", "config.py",
                "application.yml", "application.properties", "config.json"
            }:
                configs.append(f)

        return configs, dockers, ci

    def _detect_frameworks(self, files: List[str], manifests: List[str]) -> tuple[List[str], List[str]]:
        frameworks = set()
        test_frameworks = set()

        # Check manifests first
        for m in manifests:
            try:
                content = self.adapter.read_file(m, start_line=1, end_line=100).lower()
                for fw, sigs in self.FRAMEWORK_SIGNATURES.items():
                    if any(s.lower() in content for s in sigs):
                        frameworks.add(fw)
                for tf, sigs in self.TEST_FRAMEWORK_SIGNATURES.items():
                    if any(s.lower() in content for s in sigs):
                        test_frameworks.add(tf)
            except Exception:
                pass

        # Inspect up to 5 source files for framework imports if empty
        if not frameworks:
            for f in files[:10]:
                if f.endswith((".py", ".ts", ".js")):
                    try:
                        content = self.adapter.read_file(f, start_line=1, end_line=50).lower()
                        for fw, sigs in self.FRAMEWORK_SIGNATURES.items():
                            if any(s.lower() in content for s in sigs):
                                frameworks.add(fw)
                    except Exception:
                        pass

        # Inspect test files for test framework
        for f in files:
            if "test" in f.lower() and f.endswith(".py"):
                test_frameworks.add("pytest")
                break

        return sorted(list(frameworks)), sorted(list(test_frameworks))
