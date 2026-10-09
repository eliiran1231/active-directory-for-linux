"""Offline package/dependency checks. Takes a local pack output directory; never publishes."""
import json
import pathlib
import sys
import xml.etree.ElementTree as ET
import zipfile

packages = pathlib.Path(sys.argv[1])
root = pathlib.Path(__file__).resolve().parents[1]
core = "AdForLinux.DirectoryServices"
companion = core + ".MicrosoftInterop"
frameworks = {"net8.0-windows7.0", "net10.0-windows7.0"}


def manifest(name):
    candidates = list(packages.glob(name + ".*.nupkg"))
    candidates = [p for p in candidates if p.name[len(name) + 1:][0].isdigit()]
    assert len(candidates) == 1, (name, candidates)
    with zipfile.ZipFile(candidates[0]) as archive:
        names = archive.namelist()
        xml = ET.fromstring(archive.read(next(n for n in names if n.endswith(".nuspec"))))
        # Strip NuGet's namespace for stable cross-SDK inspection.
        for element in xml.iter():
            element.tag = element.tag.rsplit("}", 1)[-1]
        return xml.find("metadata"), names


core_meta, _ = manifest(core)
bridge_meta, bridge_files = manifest(companion)
assert bridge_meta.findtext("id") == companion
assert bridge_meta.findtext("version") == core_meta.findtext("version")
groups = bridge_meta.findall("dependencies/group")
assert {g.attrib["targetFramework"] for g in groups} == frameworks
for group in groups:
    deps = {d.attrib["id"]: d.attrib["version"] for d in group.findall("dependency")}
    assert deps[core] == "[" + core_meta.findtext("version") + "]", deps
    assert deps["System.DirectoryServices"] == "[9.0.0]", deps
assert {p for p in bridge_files if p.endswith(".dll")} == {
    "lib/net8.0-windows7.0/" + companion + ".dll",
    "lib/net10.0-windows7.0/" + companion + ".dll",
}

for name in [core, core + ".AccountManagement"]:
    metadata, files = manifest(name)
    dependency_ids = {d.attrib["id"] for d in metadata.findall("dependencies/group/dependency")}
    assert "System.DirectoryServices" not in dependency_ids, dependency_ids
    assert companion not in dependency_ids, dependency_ids
    for framework in ["net8.0", "net10.0"]:
        deps = json.loads((root / "src" / name / "bin" / "Release" / framework / (name + ".deps.json")).read_text())
        libraries = {key.split("/")[0] for key in deps["libraries"]}
        assert "System.DirectoryServices" not in libraries, libraries
        assert companion not in libraries, libraries
        assert "lib/" + framework + "/" + name + ".dll" in files

print("Verified optional Windows companion, exact core/native package versions, and Linux core/AccountManagement dependency isolation.")
