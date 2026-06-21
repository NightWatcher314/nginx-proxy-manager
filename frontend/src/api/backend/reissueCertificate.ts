import * as api from "./base";
import type { Certificate } from "./models";
import { paramsForAgent } from "./agentParams";

export interface CertificateReissueHostImpact {
	type: "proxy_host" | "redirection_host" | "dead_host" | "stream";
	id: number;
	domainNames?: string[];
	uncoveredDomainNames?: string[];
	incomingPort?: number;
	willDetach: boolean;
}

export interface CertificateReissueAnalysis {
	certificateId: number;
	oldDomainNames: string[];
	newDomainNames: string[];
	addedDomainNames: string[];
	removedDomainNames: string[];
	stillCovered: CertificateReissueHostImpact[];
	uncoveredHosts: CertificateReissueHostImpact[];
	blockedStreams: CertificateReissueHostImpact[];
	canReissue: boolean;
	requiresDetachConfirmation: boolean;
	challengeType: "http" | "dns";
}

export interface CertificateReissuePayload {
	domainNames: string[];
	detachUncoveredHosts?: boolean;
}

export async function analyzeCertificateReissue(id: number, payload: CertificateReissuePayload, agentId?: string): Promise<CertificateReissueAnalysis> {
	return await api.post({
		url: `/nginx/certificates/${id}/reissue/analyze`,
		params: paramsForAgent(agentId),
		data: payload,
	});
}

export async function reissueCertificate(id: number, payload: CertificateReissuePayload, agentId?: string): Promise<Certificate> {
	return await api.post({
		url: `/nginx/certificates/${id}/reissue`,
		params: paramsForAgent(agentId),
		data: payload,
	});
}
