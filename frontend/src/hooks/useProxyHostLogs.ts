import { useQuery } from "@tanstack/react-query";
import { getProxyHostLogs } from "src/api/backend";

const useProxyHostLogs = (id: number, type: "access" | "error" = "access", agentId?: string) => {
	return useQuery<{ logs: string }, Error>({
		queryKey: ["proxy-host-logs", id, type, { agentId }],
		queryFn: () => getProxyHostLogs(id, type, agentId),
		staleTime: 10_000,
	});
};

export { useProxyHostLogs };
