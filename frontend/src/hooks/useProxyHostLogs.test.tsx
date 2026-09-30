import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { expect, it, vi } from "vitest";
import { useProxyHostLogs } from "./useProxyHostLogs";

const { getProxyHostLogs } = vi.hoisted(() => ({ getProxyHostLogs: vi.fn(async (_id: number, _type: string, agentId?: string) => ({ logs: agentId || "local" })) }));
vi.mock("src/api/backend", () => ({ getProxyHostLogs }));

it("keeps logs from identical host IDs on different Agents in separate caches", async () => {
	const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
	const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
	const local = renderHook(() => useProxyHostLogs(3, "access", "local"), { wrapper });
	await waitFor(() => expect(local.result.current.data?.logs).toBe("local"));
	const remote = renderHook(() => useProxyHostLogs(3, "access", "7"), { wrapper });
	await waitFor(() => expect(remote.result.current.data?.logs).toBe("7"));
	await waitFor(() => expect(local.result.current.data?.logs).toBe("local"));
	expect(getProxyHostLogs).toHaveBeenCalledWith(3, "access", "7");
	local.unmount();
	remote.unmount();
	client.clear();
});
