import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

const workflowsDir = path.resolve(import.meta.dirname, "../../../.github/workflows");
const workflowText = readFileSync(path.join(workflowsDir, "publish-server-image.yml"), "utf8");
const publisherText = readFileSync(
  path.resolve(workflowsDir, "../actions/publish-image/action.yml"),
  "utf8",
);
interface Step {
  id?: string;
  if?: string;
  uses?: string;
  run?: string;
  with?: Record<string, unknown>;
}
interface Job {
  if?: string;
  needs?: string | string[];
  uses?: string;
  "runs-on"?: string;
  permissions?: Record<string, string>;
  strategy?: { matrix?: { image?: string[]; include?: Array<Record<string, string>> } };
  steps?: Step[];
  concurrency?: { group: string; queue?: string; "cancel-in-progress"?: boolean };
}
const workflow = parse(workflowText) as {
  on: Record<string, { inputs?: Record<string, { type: string; default: boolean }> }>;
  permissions: Record<string, string>;
  concurrency: { group: string; "cancel-in-progress": boolean };
  jobs: Record<string, Job>;
};
const ci = parse(readFileSync(path.join(workflowsDir, "ci.yml"), "utf8")) as {
  concurrency: { group: string; "cancel-in-progress": string };
  jobs: Record<string, Job>;
};
const publisher = parse(publisherText) as { runs: { steps: Step[] } };
const variants = ["app", "updater", "computer", "computer-headless"];

describe("approved fork server image publish workflow", () => {
  it("requires explicit opt-in and full validation for every publishing job", () => {
    expect(Object.keys(workflow.on).sort()).toEqual(["workflow_call", "workflow_dispatch"]);
    for (const event of Object.values(workflow.on)) {
      expect(event.inputs?.approved).toMatchObject({ type: "boolean", default: false });
    }
    expect(workflow.permissions).toEqual({ contents: "read" });
    expect(workflow.jobs["full-tests"].if).toBe("inputs.approved == true");
    expect(workflow.jobs["full-tests"].uses).toBe("./.github/workflows/fork-full-validation.yml");
    expect(workflow.jobs["full-tests"].permissions).toEqual({ contents: "read" });
    expect(workflow.jobs.build.needs).toBe("full-tests");
    expect(workflow.jobs.build.if).toBe(
      "inputs.approved == true && needs.full-tests.result == 'success'",
    );
    expect(workflow.jobs.publish.needs).toEqual(["full-tests", "build"]);
    expect(workflow.jobs.publish.if).toBe(
      "inputs.approved == true && needs.full-tests.result == 'success' && needs.build.result == 'success'",
    );
    expect(Object.keys(workflow.jobs).sort()).toEqual(["build", "full-tests", "publish"]);
  });

  it("builds all four variants natively on both architectures, including headless", () => {
    expect(workflowText).not.toContain("setup-qemu-action");
    expect(workflowText).not.toContain("depot/");
    const build = workflow.jobs.build;
    expect(build["runs-on"]).toContain("matrix.runner");
    const matrix = build.strategy?.matrix?.include ?? [];
    expect(matrix).toHaveLength(8);
    for (const image of variants) {
      const entries = matrix.filter((entry) => entry.image === image);
      expect(entries.map((entry) => entry.arch).sort()).toEqual(["amd64", "arm64"]);
      for (const entry of entries) {
        expect(entry.runner).toBe(entry.arch === "arm64" ? "ubuntu-24.04-arm" : "ubuntu-latest");
        expect(entry.desktop).toBe(image === "computer-headless" ? "0" : "1");
        expect(entry.file).toBe(
          image.startsWith("computer")
            ? "infra/sandboxes/computer/Dockerfile"
            : image === "updater"
              ? "infra/updater/Dockerfile"
              : "infra/compose/Dockerfile",
        );
      }
    }
    expect(workflow.jobs.publish.strategy?.matrix?.image).toEqual(variants);
  });

  it("scans credentials before exposing native digests and retains SBOM/provenance", () => {
    const steps = workflow.jobs.build.steps ?? [];
    const build = steps.find((step) => step.id === "image");
    expect(build?.uses).toMatch(/^docker\/build-push-action@[0-9a-f]{40}$/);
    expect(build?.with?.outputs).toContain("push-by-digest=true");
    expect(build?.with?.provenance).toBe("mode=max");
    expect(build?.with?.sbom).toBe(true);
    const scan = steps.findIndex((step) => step.run?.includes("check-image.sh"));
    expect(scan).toBeGreaterThan(steps.indexOf(build as Step));
    expect(steps[scan]?.if).toBe("matrix.image == 'app'");
    expect(steps[scan]?.run).toContain('"$IMAGE" "$PLATFORM"');
    const upload = steps.findIndex((step) => step.uses?.startsWith("actions/upload-artifact@"));
    expect(upload).toBeGreaterThan(scan);
    expect(steps[upload]?.with?.["if-no-files-found"]).toBe("error");
    // The retained upstream composite action still attests only after manifest publication.
    const manifest = publisher.runs.steps.findIndex((step) =>
      step.run?.includes('"$ACTION_PATH/publish.sh"'),
    );
    const attest = publisher.runs.steps.findIndex((step) =>
      step.uses?.startsWith("actions/attest-build-provenance@"),
    );
    expect(manifest).toBeGreaterThanOrEqual(0);
    expect(attest).toBeGreaterThan(manifest);
  });

  it("publishes only immutable SHA indexes from exactly two native digests", () => {
    const steps = workflow.jobs.publish.steps ?? [];
    const publish = steps.find((step) => step.run?.includes("imagetools create"));
    expect(publish?.run).toContain('test "${#files[@]}" = 2');
    expect(publish?.run).toContain('"$IMAGE@sha256:$(basename "$file")"');
    expect(publish?.run).toContain('imagetools create -t "$IMAGE:sha-$SOURCE_SHA" "${refs[@]}"');
    expect(publish?.run).toContain('imagetools inspect "$IMAGE:sha-$SOURCE_SHA"');
    expect(publish?.run).toContain("GITHUB_STEP_SUMMARY");
    expect(publish?.run).not.toMatch(/:(edge|latest)\b/);
    expect(steps.some((step) => step.uses?.startsWith("actions/upload-artifact@"))).toBe(true);
    for (const job of [workflow.jobs.build, workflow.jobs.publish]) {
      expect(job.permissions).toEqual({ contents: "read", packages: "write" });
    }
    expect(workflowText).not.toMatch(/dokploy|deploy-production|deploy\.sh/);
  });

  it("keeps the upstream CI publishing call gated by the fork's default-deny input", () => {
    const publish = ci.jobs["publish-server-image"];
    expect(publish?.uses).toBe("./.github/workflows/publish-server-image.yml");
    expect(publish?.if).toBe("github.event_name == 'push' && github.ref == 'refs/heads/main'");
    expect(workflow.on.workflow_call.inputs?.approved.default).toBe(false);
    expect(ci.jobs["deploy-production"]?.needs).toEqual([
      "checks",
      "test-integration",
      "publish-server-image",
    ]);
  });

  it("never cancels an approved running publication and retains upstream CI queue safeguards", () => {
    expect(workflow.concurrency.group).toContain("github.ref");
    expect(workflow.concurrency["cancel-in-progress"]).toBe(false);
    expect(ci.concurrency.group).toContain("github.run_id");
    expect(ci.concurrency.group).toContain("github.event.pull_request.number");
    // biome-ignore lint/suspicious/noTemplateCurlyInString: literal GitHub Actions expression
    expect(ci.concurrency["cancel-in-progress"]).toBe("${{ github.event_name == 'pull_request' }}");
    for (const name of ["deploy-production", "publish-mobile-update"]) {
      expect(ci.jobs[name]?.concurrency?.queue).toBe("max");
      expect(ci.jobs[name]?.concurrency?.["cancel-in-progress"]).toBe(false);
    }
    const names = [
      "static-checks",
      "unit-tests-shard",
      "test-integration-shard",
      "publish-server-image",
    ];
    const locks = names.map((name) => ci.jobs[name]?.concurrency);
    expect(new Set(locks.map((lock) => lock?.group)).size).toBe(locks.length);
    for (const lock of locks) {
      expect(lock?.group).toMatch(/main/);
      expect(lock?.queue).toBeUndefined();
      expect(lock?.["cancel-in-progress"]).toBeUndefined();
    }
    for (const name of names) expect(ci.jobs[name]?.needs, name).toBeUndefined();
  });

  it("pins every third-party action and prevents checkout credential persistence", () => {
    for (const text of [workflowText, publisherText]) {
      for (const match of text.matchAll(/uses:\s+([^\s#]+)/g)) {
        if (match[1]?.startsWith("./")) continue;
        expect(match[1], match[1]).toMatch(/@[0-9a-f]{40}$/);
      }
    }
    const checkout = workflow.jobs.build.steps?.find((step) =>
      step.uses?.startsWith("actions/checkout@"),
    );
    expect(checkout?.with?.["persist-credentials"]).toBe(false);
  });
});
