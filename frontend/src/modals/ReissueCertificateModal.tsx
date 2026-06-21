import { IconAlertTriangle, IconRefresh } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { Field, Form, Formik } from "formik";
import { type ReactNode, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import {
	analyzeCertificateReissue,
	reissueCertificate,
	type CertificateReissueAnalysis,
	type CertificateReissueHostImpact,
} from "src/api/backend";
import { Button, DomainNamesField, Loading } from "src/components";
import { useCertificate } from "src/hooks";
import { T } from "src/locale";
import { showObjectSuccess } from "src/notifications";

interface Props extends InnerModalProps {
	id: number;
	agentId?: string;
	agentName?: string;
}

const showReissueCertificateModal = (id: number, agentId?: string, agentName?: string) => {
	EasyModal.show(ReissueCertificateModal as any, { id, agentId, agentName });
};

const hostLabel = (host: CertificateReissueHostImpact) => {
	const type = host.type.replace(/_/g, " ");
	if (host.type === "stream") {
		return `${type} #${host.id}${host.incomingPort ? `:${host.incomingPort}` : ""}`;
	}
	return `${type} #${host.id}: ${(host.domainNames || []).join(", ")}`;
};

const DomainList = ({ title, domains }: { title: string; domains: string[] }) => {
	if (!domains.length) return null;
	return (
		<div className="mb-3">
			<strong>{title}</strong>
			<ul className="mb-0">
				{domains.map((domain) => (
					<li key={domain}>{domain}</li>
				))}
			</ul>
		</div>
	);
};

const HostList = ({ title, hosts }: { title: string; hosts: CertificateReissueHostImpact[] }) => {
	if (!hosts.length) return null;
	return (
		<div className="mb-3">
			<strong>{title}</strong>
			<ul className="mb-0">
				{hosts.map((host) => (
					<li key={`${host.type}-${host.id}`}>
						{hostLabel(host)}
						{host.uncoveredDomainNames?.length ? (
							<div className="text-muted small">
								No longer covered: {host.uncoveredDomainNames.join(", ")}
								{host.willDetach ? "; will detach certificate and disable Force SSL / HSTS / HTTP2" : ""}
							</div>
						) : null}
					</li>
				))}
			</ul>
		</div>
	);
};

const ReissueCertificateModal = EasyModal.create(({ id, agentId, agentName, visible, remove }: Props) => {
	const queryClient = useQueryClient();
	const { data, isLoading, error } = useCertificate(id, {}, agentId);
	const [errorMsg, setErrorMsg] = useState<ReactNode | null>(null);
	const [analysis, setAnalysis] = useState<CertificateReissueAnalysis | null>(null);
	const [isAnalyzing, setIsAnalyzing] = useState(false);
	const [isSubmitting, setIsSubmitting] = useState(false);

	const handleAnalyze = async (values: any) => {
		setIsAnalyzing(true);
		setErrorMsg(null);
		setAnalysis(null);
		try {
			const result = await analyzeCertificateReissue(
				id,
				{
					domainNames: values.domainNames,
					detachUncoveredHosts: values.detachUncoveredHosts,
				},
				agentId,
			);
			setAnalysis(result);
		} catch (err: any) {
			setErrorMsg(<T id={err.message} />);
		} finally {
			setIsAnalyzing(false);
		}
	};

	const handleSubmit = async (values: any, { setSubmitting }: any) => {
		if (!analysis?.canReissue || isSubmitting) return;
		setIsSubmitting(true);
		setErrorMsg(null);
		try {
			await reissueCertificate(
				id,
				{
					domainNames: values.domainNames,
					detachUncoveredHosts: values.detachUncoveredHosts,
				},
				agentId,
			);
			showObjectSuccess("certificate", "saved");
			queryClient.invalidateQueries({ queryKey: ["certificates"] });
			queryClient.invalidateQueries({ queryKey: ["certificate", id] });
			remove();
		} catch (err: any) {
			setErrorMsg(<T id={err.message} />);
		} finally {
			setIsSubmitting(false);
			setSubmitting(false);
		}
	};

	const dangerousDetach = !!analysis?.requiresDetachConfirmation;

	return (
		<Modal show={visible} onHide={isSubmitting || isAnalyzing ? undefined : remove} size="lg">
			<Formik
				enableReinitialize
				initialValues={{
					domainNames: data?.domainNames || [],
					detachUncoveredHosts: false,
					confirmation: "",
				}}
				onSubmit={handleSubmit}
			>
				{({ values, setFieldValue }) => {
					const confirmationOk = !dangerousDetach || values.confirmation === "REISSUE";
					const canConfirm = !!analysis?.canReissue && confirmationOk;
					return (
						<Form>
							<Modal.Header closeButton={!isSubmitting && !isAnalyzing}>
								<Modal.Title>
									<IconRefresh size={18} className="me-1" /> Reissue Certificate #{id}{agentName ? ` on ${agentName}` : ""}
								</Modal.Title>
							</Modal.Header>
							<Modal.Body>
								<Alert variant="danger" show={!!errorMsg} onClose={() => setErrorMsg(null)} dismissible>
									{errorMsg}
								</Alert>
								{isLoading && <Loading noLogo />}
								{!isLoading && error && <Alert variant="danger">{error.message || "Unknown error"}</Alert>}
								{data ? (
									<>
										<Alert variant="warning">
											<IconAlertTriangle size={16} className="me-1" /> This requests a replacement Let's Encrypt
											certificate for the same NPM certificate ID. Run analysis before confirming.
										</Alert>
										<p className="text-muted mb-2">
											Challenge: <strong>{data.meta?.dnsChallenge ? "DNS" : "HTTP"}</strong>
										</p>
										<DomainNamesField
											isWildcardPermitted={!!data.meta?.dnsChallenge}
											dnsProviderWildcardSupported={!!data.meta?.dnsChallenge}
											onChange={() => setAnalysis(null)}
										/>
										{analysis?.uncoveredHosts.length || values.detachUncoveredHosts ? (
											<div className="form-check mb-3">
												<input
													id="detachUncoveredHosts"
													className="form-check-input"
													type="checkbox"
													checked={values.detachUncoveredHosts}
													onChange={(e) => {
														setFieldValue("detachUncoveredHosts", e.target.checked);
														setAnalysis(null);
													}}
												/>
												<label className="form-check-label" htmlFor="detachUncoveredHosts">
													Detach uncovered Proxy/Redirection/Dead Hosts and disable Force SSL / HSTS / HTTP2
												</label>
											</div>
										) : null}
										{analysis ? (
											<div className="border rounded p-3 bg-light">
												<DomainList title="Added domains" domains={analysis.addedDomainNames} />
												<DomainList title="Removed domains" domains={analysis.removedDomainNames} />
												<HostList title="Objects still covered" hosts={analysis.stillCovered} />
												<HostList title="Objects no longer covered" hosts={analysis.uncoveredHosts} />
												<HostList title="Blocked streams" hosts={analysis.blockedStreams} />
												{analysis.canReissue ? (
													<Alert variant="success" className="mb-0">Analysis passed. You can reissue this certificate.</Alert>
												) : (
													<Alert variant="danger" className="mb-0">
														Reissue is blocked. Resolve uncovered hosts, enable detach, or keep stream coverage.
													</Alert>
												)}
											</div>
										) : null}
										{dangerousDetach ? (
											<Field name="confirmation">
												{({ field }: any) => (
													<div className="mt-3">
														<label className="form-label" htmlFor="confirmation">
															Type REISSUE to confirm host detach
														</label>
														<input id="confirmation" className="form-control" autoComplete="off" {...field} />
													</div>
												)}
											</Field>
										) : null}
									</>
								) : null}
							</Modal.Body>
							<Modal.Footer>
								<Button data-bs-dismiss="modal" onClick={remove} disabled={isSubmitting || isAnalyzing}>
									<T id="cancel" />
								</Button>
								<div className="ms-auto">
									<Button
										type="button"
										actionType="secondary"
										className="me-3"
										isLoading={isAnalyzing}
										disabled={isSubmitting || !values.domainNames.length}
										onClick={() => handleAnalyze(values)}
									>
										Analyze changes
									</Button>
									<Button type="submit" actionType="primary" className="bg-pink" isLoading={isSubmitting} disabled={!canConfirm || isAnalyzing}>
										Confirm Reissue
									</Button>
								</div>
							</Modal.Footer>
						</Form>
					);
				}}
			</Formik>
		</Modal>
	);
});

export { showReissueCertificateModal };
