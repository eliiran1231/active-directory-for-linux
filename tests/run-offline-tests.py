#!/usr/bin/env python3
"""Run only reviewed offline classes, with live fixture/bind access disabled."""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
GROUPS = {
    "functional": ("AdForLinux.FunctionalTests", [
        "CoreSidTests", "SecurityDescriptorCodecTests", "MicrosoftObservableProjectorTests",
        "AclMutationEngineTests", "AclMutationReplayTests", "PortableSecurityFoundationTests",
        "V1PrincipalAuditTests", "Issue216RegressionTests", "AccountManagementPublicTypesTests",
        "PrincipalValueCollectionTests", "OfflineExecutionGuardTests", "ConnectionPoolTests", "ConnectionPoolOperationTests", "LdapWorkerDeploymentTests",
        "WindowsContextScopedReadTests",
    ]),
    "surface": ("AdForLinux.DifferentialTests", [
        "LowLevelPublicSurfaceComparisonTests", "PublicApiSurfaceComparisonTests",
        "PublicTypeModifierComparisonTests", "PrincipalSurfaceComparisonTests",
        "PortableSecurityContractTests", "V1ServiceNameTrackingComparisonTests", "OfflineExecutionGuardTests",
    ]),
    "companion": ("AdForLinux.MicrosoftInterop.Tests", [
        "CompanionTests", "RuleConversionTests", "LayoutRelocationTests", "ReviewCorrectionTests",
        "PublicIdentityHelperTests", "IdenticalEntryInteropTests",
    ]),
}
EXTRA = {
    "functional": ["CollectionCompatibilityTests", "DirectorySearcherConstructorFilterTests"],
    # Reviewed detached/delegate-backed comparisons: no directory fixture or bind.
    "surface": ["SchemaNameCollectionComparisonTests", "SearcherConstructorFilterComparisonTests",
                "SearcherValidationContractComparisonTests"],
}


def prepare(group, framework, classes=None, dotnet="dotnet", results_directory=None):
    if group not in GROUPS or framework not in ("net8.0", "net10.0"):
        raise ValueError("Unknown offline group or runtime.")
    project, defaults = GROUPS[group]
    selected = defaults if classes is None else classes
    allowed = set(defaults + EXTRA.get(group, []))
    if not selected or any(name not in allowed for name in selected):
        raise ValueError("Only exact reviewed offline class names are accepted; live classes and raw filters are forbidden.")
    # The final dot is deliberate: ClassSuffix and similarly named live classes
    # cannot match. Callers cannot supply a raw filter or arbitrary dotnet args.
    test_filter = "|".join(f"FullyQualifiedName~{project}.{name}." for name in dict.fromkeys(selected))
    target = framework if group == "functional" else framework + "-windows"
    # Always build current sources: --no-build could silently run an old assembly
    # that has neither the fixture guard nor the pre-native LDAP guard.
    command = [dotnet, "test", f"tests/{project}/{project}.csproj", "--configuration", "Release",
               "--framework", target, "--no-restore", "--filter", test_filter]
    if results_directory:
        label = {"functional": "acl-offline", "surface": "public-surface", "companion": "companion"}[group]
        command += ["--logger", f"trx;LogFileName={label}-{framework}.trx",
                    "--results-directory", results_directory]
    environment = os.environ.copy()
    environment["ADFL_OFFLINE_TESTS"] = "1"
    return command, environment


def run(group, framework, classes=None, dotnet="dotnet", results_directory=None, check_only=False):
    command, environment = prepare(group, framework, classes, dotnet, results_directory)
    if check_only:
        print(json.dumps({"command": command, "offline_mode": environment["ADFL_OFFLINE_TESTS"]}))
        return 0
    return subprocess.run(command, cwd=ROOT, env=environment, check=False).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("group", choices=GROUPS)
    parser.add_argument("--framework", required=True, choices=["net8.0", "net10.0"])
    parser.add_argument("--class", action="append", dest="classes", help="Exact allowlisted class; repeat to select several.")
    parser.add_argument("--dotnet", default="dotnet")
    parser.add_argument("--results-directory")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    try:
        return run(args.group, args.framework, args.classes, args.dotnet, args.results_directory, args.check_only)
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
