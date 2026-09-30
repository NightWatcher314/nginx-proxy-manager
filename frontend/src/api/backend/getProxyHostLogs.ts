import * as api from "./base";
import { paramsForAgent } from "./agentParams";

export async function getProxyHostLogs(id: number, type: "access" | "error" = "access", agentId?: string): Promise<{ logs: string }> {
	return await api.get({
		url: `/nginx/proxy-hosts/${id}/logs`,
		params: { type, ...paramsForAgent(agentId) },
	});
}
