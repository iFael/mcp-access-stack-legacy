import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { SshWorkspaceExecutor } from "../../../src/remote/ssh-workspace-executor.js";
import type {
  RemoteBytesResult,
  RemoteDirectoryListing,
  RemoteProcessResult,
  RemoteWriteResult,
  SshWindowsTransport,
} from "../../../src/remote/ssh-windows-transport.js";

const SHA_A = "a".repeat(40);
const SHA_B = "b".repeat(40);
const SHA_C = "c".repeat(40);
const SHA_D = "d".repeat(40);

function remoteResult(
  stdout = "",
  exitCode: number | null = 0,
): RemoteProcessResult {
  return { exitCode, stdout, stderr: "", timedOut: false };
}

function queueRepository(
  transport: FakeTransport,
  topLevel = "C:/workspace",
): void {
  transport.execResults.push(
    remoteResult("true\n"),
    remoteResult(`${topLevel}\n`),
  );
}

class FakeTransport {
  readonly files = new Map<string, Buffer>([
    ["README.md", Buffer.from("line one\nline two\n", "utf8")],
  ]);
  commands: Array<{ shell: string; command: string; cwd: string }> = [];
  execCommands: Array<{ executable: string; argv: string[]; cwd: string }> = [];
  execResults: RemoteProcessResult[] = [];

  async probeRoot() {
    return { fullPath: "C:\\workspace", kind: "directory" as const };
  }

  async list(): Promise<RemoteDirectoryListing> {
    return {
      entries: [...this.files.entries()].map(([filePath, value]) => ({
        path: filePath,
        kind: "file" as const,
        sizeBytes: value.byteLength,
      })),
      truncated: false,
    };
  }

  async readBytes(_root: string, logicalPath: string): Promise<RemoteBytesResult> {
    const value = this.files.get(logicalPath);
    if (!value) throw new Error("missing fake file");
    return {
      contentBase64: value.toString("base64"),
      sizeBytes: value.byteLength,
      sha256: sha256(value),
    };
  }

  async writeBytes(
    _root: string,
    logicalPath: string,
    value: Buffer,
    options: { expectedSha256?: string },
  ): Promise<RemoteWriteResult> {
    const before = this.files.get(logicalPath);
    if (before && options.expectedSha256 && sha256(before) !== options.expectedSha256) {
      throw new Error("hash mismatch");
    }
    this.files.set(logicalPath, Buffer.from(value));
    return { created: !before, sizeBytes: value.byteLength, sha256: sha256(value) };
  }

  async runShell(
    _root: string,
    cwd: string,
    shell: string,
    command: string,
  ): Promise<RemoteProcessResult> {
    this.commands.push({ shell, command, cwd });
    return { exitCode: 0, stdout: "ok\n", stderr: "", timedOut: false };
  }

  async exec(_root: string, cwd: string, executable: string, argv: string[]): Promise<RemoteProcessResult> {
    this.execCommands.push({ executable, argv, cwd });
    return this.execResults.shift() ?? remoteResult("main\n");
  }
}

describe("SshWorkspaceExecutor", () => {
  let stateDirectory: string;
  let transport: FakeTransport;
  let executor: SshWorkspaceExecutor;

  beforeEach(async () => {
    stateDirectory = await mkdtemp(path.join(os.tmpdir(), "mcp-ssh-executor-"));
    transport = new FakeTransport();
    executor = await SshWorkspaceExecutor.create({
      policy: {
        version: 1,
        workspaces: [
          {
            id: "test",
            name: "Test",
            rootPath: "C:\\workspace",
            workspaceKind: "repository",
            enabled: true,
            permissionProfile: "full-repo-write",
            confirmationMode: "standard",
            allowedRoots: ["."],
            blockedGlobs: ["private/**"],
            limits: {
              maxFileBytes: 64_000,
              maxSearchResults: 100,
              maxSearchSnippetBytes: 20_000,
              maxDiffBytes: 500_000,
              maxListedFiles: 500,
            },
            allowWrites: ["."],
            allowShell: ["."],
            allowedShells: ["powershell", "pwsh"],
          },
        ],
      },
      backgroundStateDirectory: stateDirectory,
      transport: transport as unknown as SshWindowsTransport,
    });
  });

  afterEach(async () => {
    await rm(stateDirectory, { recursive: true, force: true });
  });

  it("reads and writes through the SSH transport without changing MCP contracts", async () => {
    const read = await executor.readFile({ workspaceId: "test", path: "README.md" });
    expect(read).toMatchObject({
      path: "README.md",
      content: "line one\nline two\n",
      encoding: "utf-8",
    });

    const written = await executor.writeFile({
      workspaceId: "test",
      path: "src/new.txt",
      content: "remote\n",
    });
    expect(written).toMatchObject({ path: "src/new.txt", created: true });
    expect(transport.files.get("src/new.txt")?.toString("utf8")).toBe("remote\n");
  });

  it("keeps blocked paths server-side", async () => {
    await expect(
      executor.readFile({ workspaceId: "test", path: "private/secret.txt" }),
    ).rejects.toMatchObject({ code: "BLOCKED_PATH" });
  });

  it("requires confirmation before dispatching a destructive remote shell command", async () => {
    const first = await executor.runCommand({
      workspaceId: "test",
      shell: "powershell",
      command: "Remove-Item -LiteralPath .\\obsolete.txt",
      timeoutMs: 30_000,
    });
    expect(first.status).toBe("confirmation_required");
    expect(transport.commands).toHaveLength(0);
    if (first.status !== "confirmation_required") throw new Error("expected confirmation");

    const second = await executor.runCommand({
      workspaceId: "test",
      shell: "powershell",
      command: "Remove-Item -LiteralPath .\\obsolete.txt",
      timeoutMs: 30_000,
      confirmationId: first.confirmationId,
    });
    expect(second.status).toBe("executed");
    expect(transport.commands).toHaveLength(1);
  });

  it("routes main push to confirmation without probing the current branch", async () => {
    const result = await executor.runCommand({
      workspaceId: "test",
      shell: "powershell",
      command: "git push origin main",
      timeoutMs: 30_000,
    });

    expect(result).toMatchObject({
      status: "confirmation_required",
      reasons: expect.arrayContaining(["git push requires explicit user confirmation"]),
    });
    expect(transport.execCommands).toHaveLength(0);
    expect(transport.commands).toHaveLength(0);
  });

  it("fails closed for interactive background tasks and persistent stdin over SSH", async () => {
    await expect(
      executor.startBackgroundTask({
        workspaceId: "test",
        operation: "remote-interactive",
        shell: "powershell",
        command: "Write-Output 'never-runs'",
        timeoutMs: 30_000,
        interactive: true,
      }),
    ).rejects.toMatchObject({ code: "CAPABILITY_UNSUPPORTED" });
    expect(transport.commands).toHaveLength(0);

    await expect(
      executor.writeBackgroundTaskStdin({
        workspaceId: "test",
        id: "123e4567-e89b-42d3-a456-426614174099",
        input: "hello\n",
      }),
    ).rejects.toMatchObject({ code: "CAPABILITY_UNSUPPORTED" });
  });

  it("uses the same confirmation flow for risky remote background tasks", async () => {
    const input = {
      workspaceId: "test",
      operation: "remote-cleanup",
      shell: "powershell" as const,
      command: "Remove-Item -LiteralPath .\\obsolete.txt -Force",
      timeoutMs: 30_000,
    };

    const pending = await executor.startBackgroundTask(input);
    expect(pending).toMatchObject({
      status: "confirmation_required",
      reasons: expect.arrayContaining(["delete, remove or force-clean operation"]),
    });
    expect(transport.commands).toHaveLength(0);
    if (pending.status !== "confirmation_required") throw new Error("expected confirmation");

    const started = await executor.startBackgroundTask({
      ...input,
      confirmationId: pending.confirmationId,
    });
    expect(started).toMatchObject({
      status: "background_task_started",
      task: { operation: input.operation },
    });
    if (started.status !== "background_task_started") throw new Error("expected background task");
    expect(JSON.stringify(started.task)).not.toContain("confirmationId");
    expect(JSON.stringify(started.task)).not.toContain(pending.confirmationId);

    await expect(
      executor.startBackgroundTask({
        ...input,
        confirmationId: pending.confirmationId,
      }),
    ).rejects.toMatchObject({ code: "COMMAND_CONFIRMATION_INVALID" });
  });
  it("isolates remote background task lookup and listing by owner scope", async () => {
    const ownerA = { ownerScope: "openai-session:ssh-owner-a" };
    const ownerB = { ownerScope: "openai-session:ssh-owner-b" };
    const started = await executor.startBackgroundTask(
      {
        workspaceId: "test",
        operation: "remote-owner-check",
        shell: "powershell",
        command: "Write-Output 'owned'",
        timeoutMs: 30_000,
      },
      ownerA,
    );
    if (started.status !== "background_task_started") {
      throw new Error("expected background task");
    }

    expect(
      (
        await executor.getBackgroundTask(
          { workspaceId: "test", id: started.task.id },
          ownerA,
        )
      ).task?.id,
    ).toBe(started.task.id);
    expect(
      (
        await executor.getBackgroundTask(
          { workspaceId: "test", id: started.task.id },
          ownerB,
        )
      ).task,
    ).toBeNull();
    expect(
      (await executor.listBackgroundTasks({ workspaceId: "test" }, ownerA))
        .tasks.map((task) => task.id),
    ).toContain(started.task.id);
    expect(
      (await executor.listBackgroundTasks({ workspaceId: "test" }, ownerB))
        .tasks.map((task) => task.id),
    ).not.toContain(started.task.id);

    await executor.cancelBackgroundTask(
      { workspaceId: "test", id: started.task.id },
      ownerA,
    );
  });

  it("requires the selected remote root to be the Git top-level", async () => {
    queueRepository(transport, "C:/parent");

    await expect(
      executor.stagePaths({
        workspaceId: "test",
        paths: ["README.md"],
      }),
    ).rejects.toMatchObject({ code: "NOT_GIT_REPOSITORY" });

    expect(transport.execCommands.map((entry) => entry.argv)).toEqual([
      ["rev-parse", "--is-inside-work-tree"],
      ["rev-parse", "--show-toplevel"],
    ]);
  });

  it("creates a typed feature branch remotely with exact HEAD preconditions", async () => {
    queueRepository(transport);
    transport.execResults.push(
      remoteResult(`${SHA_A}\n`),
      remoteResult("", 128),
      remoteResult(),
      remoteResult(`${SHA_A}\n`),
    );

    const result = await executor.createBranch({
      workspaceId: "test",
      branch: "feature/ssh",
      expectedHeadSha: SHA_A,
    });

    expect(result).toEqual({
      root: ".",
      branch: "feature/ssh",
      headSha: SHA_A,
    });
    const mutation = transport.execCommands.at(-2);
    expect(mutation?.executable).toBe("git");
    expect(mutation?.argv.slice(-4)).toEqual([
      "switch",
      "-c",
      "feature/ssh",
      SHA_A,
    ]);
    expect(mutation?.argv).toEqual(expect.arrayContaining([
      "-c",
      "commit.gpgSign=false",
      "merge.gpgSign=false",
    ]));
  });

  it("stages and unstages only explicit authorized remote paths", async () => {
    queueRepository(transport);
    transport.execResults.push(
      remoteResult(),
      remoteResult(`${SHA_A}\n`),
      remoteResult(`${SHA_B}\n`),
    );
    const staged = await executor.stagePaths({
      workspaceId: "test",
      paths: ["src/a.ts"],
    });
    expect(staged).toEqual({
      root: ".",
      headSha: SHA_A,
      indexTreeSha: SHA_B,
      paths: ["src/a.ts"],
    });
    expect(transport.execCommands.at(-3)?.argv.slice(-3)).toEqual([
      "add",
      "--",
      "src/a.ts",
    ]);

    transport.execCommands.length = 0;
    queueRepository(transport);
    transport.execResults.push(
      remoteResult(`${SHA_A}\n`),
      remoteResult(`${SHA_B}\n`),
      remoteResult(),
      remoteResult(`${SHA_A}\n`),
      remoteResult(`${SHA_C}\n`),
    );
    const unstaged = await executor.unstagePaths({
      workspaceId: "test",
      paths: ["src/a.ts"],
      expectedHeadSha: SHA_A,
      expectedIndexTreeSha: SHA_B,
    });
    expect(unstaged).toEqual({
      root: ".",
      headSha: SHA_A,
      indexTreeSha: SHA_C,
      paths: ["src/a.ts"],
    });
    expect(transport.execCommands.at(-3)?.argv.slice(-4)).toEqual([
      "restore",
      "--staged",
      "--",
      "src/a.ts",
    ]);
  });

  it("blocks remote staging paths denied by workspace policy", async () => {
    queueRepository(transport);

    await expect(
      executor.stagePaths({
        workspaceId: "test",
        paths: ["private/secret.txt"],
      }),
    ).rejects.toMatchObject({ code: "BLOCKED_PATH" });

    expect(transport.execCommands).toHaveLength(2);
  });

  it("commits remotely only after exact branch, HEAD and index checks", async () => {
    queueRepository(transport);
    transport.execResults.push(
      remoteResult("feature/ssh\n"),
      remoteResult(`${SHA_A}\n`),
      remoteResult(`${SHA_B}\n`),
      remoteResult(),
      remoteResult(`${SHA_C}\n`),
    );

    const result = await executor.commit({
      workspaceId: "test",
      message: "feat: remote typed git",
      expectedHeadSha: SHA_A,
      expectedIndexTreeSha: SHA_B,
    });

    expect(result).toEqual({
      root: ".",
      branch: "feature/ssh",
      commitSha: SHA_C,
    });
    expect(transport.execCommands.at(-2)?.argv.slice(-3)).toEqual([
      "commit",
      "-m",
      "feat: remote typed git",
    ]);

    transport.execCommands.length = 0;
    queueRepository(transport);
    transport.execResults.push(remoteResult("main\n"));
    await expect(
      executor.commit({
        workspaceId: "test",
        message: "blocked",
        expectedHeadSha: SHA_A,
        expectedIndexTreeSha: SHA_B,
      }),
    ).rejects.toMatchObject({ code: "GIT_PROTECTED_BRANCH" });
    expect(transport.execCommands).toHaveLength(3);
  });

  it("fast-forwards a remote branch only after clean exact preconditions", async () => {
    queueRepository(transport);
    transport.execResults.push(
      remoteResult("dev\n"),
      remoteResult(`${SHA_A}\n`),
      remoteResult(`${SHA_B}\n`),
      remoteResult("", 0),
      remoteResult("", 0),
      remoteResult("", 0),
      remoteResult(),
      remoteResult(`${SHA_B}\n`),
    );

    const result = await executor.mergeBranch({
      workspaceId: "test",
      sourceBranch: "feature/source",
      expectedTargetHeadSha: SHA_A,
      expectedSourceHeadSha: SHA_B,
    });

    expect(result).toEqual({
      root: ".",
      branch: "dev",
      previousHeadSha: SHA_A,
      headSha: SHA_B,
      sourceHeadSha: SHA_B,
      fastForwarded: true,
    });
    expect(transport.execCommands.at(-2)?.argv.slice(-3)).toEqual([
      "merge",
      "--ff-only",
      SHA_B,
    ]);
  });

  it("reconciles an ambiguous remote push before reporting completion", async () => {
    queueRepository(transport);
    transport.execResults.push(
      remoteResult(`${SHA_C}\n`),
      remoteResult(`${SHA_A}\trefs/heads/feature/ssh\n`),
      remoteResult("", 1),
      remoteResult(`${SHA_C}\trefs/heads/feature/ssh\n`),
    );

    const result = await executor.pushBranch({
      workspaceId: "test",
      branch: "feature/ssh",
      expectedLocalSha: SHA_C,
      remote: "origin",
      expectedRemoteSha: SHA_A,
    });

    expect(result).toEqual({
      status: "completed",
      root: ".",
      remote: "origin",
      branch: "feature/ssh",
      localSha: SHA_C,
      remoteSha: SHA_C,
    });
    const push = transport.execCommands.at(-2);
    expect(push?.argv.slice(-3)).toEqual([
      "push",
      "origin",
      `${SHA_C}:refs/heads/feature/ssh`,
    ]);
  });

  it("requires reconciliation when an ambiguous remote push resolves elsewhere", async () => {
    queueRepository(transport);
    transport.execResults.push(
      remoteResult(`${SHA_C}\n`),
      remoteResult(`${SHA_A}\trefs/heads/feature/ssh\n`),
      remoteResult("", 1),
      remoteResult(`${SHA_D}\trefs/heads/feature/ssh\n`),
    );

    await expect(
      executor.pushBranch({
        workspaceId: "test",
        branch: "feature/ssh",
        expectedLocalSha: SHA_C,
        remote: "origin",
        expectedRemoteSha: SHA_A,
      }),
    ).rejects.toMatchObject({ code: "SOURCE_CONTROL_RECONCILIATION_REQUIRED" });
  });

  it("keeps typed GitHub operations unsupported without touching the SSH transport", async () => {
    const methods = [
      "getRepository",
      "createRepository",
      "getPullRequest",
      "createPullRequest",
      "mergePullRequest",
    ] as const;

    for (const method of methods) {
      await expect((executor as any)[method]({ workspaceId: "test" })).rejects.toMatchObject({
        code: "CAPABILITY_UNSUPPORTED",
      });
    }
    expect(transport.commands).toHaveLength(0);
    expect(transport.execCommands).toHaveLength(0);
  });
});

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}
