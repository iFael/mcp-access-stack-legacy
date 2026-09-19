import { describe, expect, test, jest } from "@jest/globals";
import type { Request, Response } from "express";
import type { Logger } from "pino";
import {
  createChallenge,
  createMcpTransportObservationMiddleware,
  createOriginMiddleware,
  isMcpInitializeRequest,
  isToolCall,
  resolveMcpTransportMode,
  type AuthenticatedRequest,
} from "../../../src/http/mcp-middleware.js";

describe("MCP HTTP middleware helpers", () => {
  test("builds the OAuth challenge and detects only tool calls", () => {
    expect(
      createChallenge(
        new URL("https://gateway.example/.well-known/oauth-protected-resource/mcp"),
        "workspaces:read",
      ),
    ).toBe(
      'Bearer resource_metadata="https://gateway.example/.well-known/oauth-protected-resource/mcp", scope="workspaces:read"',
    );
    expect(isToolCall({ method: "tools/call" })).toBe(true);
    expect(isToolCall({ method: "tools/list" })).toBe(false);
    expect(isToolCall(null)).toBe(false);
  });

  test("classifies stateless and stateful MCP transport without exposing session ids", () => {
    expect(resolveMcpTransportMode("stateless", "POST", { method: "initialize" }, true)).toBe("stateless");
    expect(resolveMcpTransportMode("stateful-experiment", "POST", { method: "initialize" }, false)).toBe("stateful");
    expect(resolveMcpTransportMode("stateful-experiment", "POST", { method: "tools/list" }, true)).toBe("stateful");
    expect(resolveMcpTransportMode("stateful-experiment", "POST", { method: "tools/list" }, false)).toBe("stateless");
    expect(isMcpInitializeRequest({ method: "initialize" })).toBe(true);
    expect(isMcpInitializeRequest([{ method: "initialize" }])).toBe(false);

    const info = jest.fn();
    const next = jest.fn();
    const request = {
      method: "POST",
      body: { method: "initialize" },
      mcpRequestId: "request-1",
      header: (name: string) => name.toLowerCase() === "mcp-session-id"
        ? "secret-session-id-must-not-be-logged"
        : undefined,
    } as unknown as AuthenticatedRequest;
    createMcpTransportObservationMiddleware(
      { info } as unknown as Logger,
      "stateful-experiment",
    )(request, {} as Response, next);

    expect(request.mcpTransportMode).toBe("stateful");
    expect(request.mcpSessionIdPresent).toBe(true);
    expect(next).toHaveBeenCalledTimes(1);
    expect(info).toHaveBeenCalledWith({
      event: "mcp_http_transport_selected",
      requestId: "request-1",
      mcpTransportMode: "stateful",
      mcpSessionIdPresent: true,
    });
    expect(JSON.stringify(info.mock.calls)).not.toContain("secret-session-id-must-not-be-logged");
  });

  test("allows missing or trusted origins and rejects an untrusted origin", () => {
    const middleware = createOriginMiddleware(new Set(["https://chatgpt.com"]));
    const next = jest.fn();
    const response = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    } as unknown as Response;

    middleware(
      { header: () => undefined } as unknown as Request,
      response,
      next,
    );
    middleware(
      { header: () => "https://chatgpt.com" } as unknown as Request,
      response,
      next,
    );
    middleware(
      { header: () => "https://evil.example" } as unknown as Request,
      response,
      next,
    );

    expect(next).toHaveBeenCalledTimes(2);
    expect(response.status).toHaveBeenCalledWith(403);
    expect(response.json).toHaveBeenCalledWith({ error: "origin_not_allowed" });
  });
});
