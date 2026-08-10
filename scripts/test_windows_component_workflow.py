from pathlib import Path


workflow = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "windows-component.yml"
)
assert workflow.is_file(), "missing n00b-owned Windows validation workflow"
text = workflow.read_text(encoding="utf-8")

for contract in (
    "workflow_dispatch:",
    "ncc_run_id:",
    "ncc_sha:",
    "repository: crashappsec/ncc",
    "run-id: ${{ inputs.ncc_run_id }}",
    "github-token: ${{ github.token }}",
    ".\\build.ps1",
    "meson test",
    "condition",
    "actions/upload-artifact@",
):
    assert contract in text, f"missing Windows workflow contract: {contract}"

assert "Build NCC" not in text, "n00b must consume NCC's artifact instead of rebuilding it"
print("n00b Windows workflow contract: pass")
