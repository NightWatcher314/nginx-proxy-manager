import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import test from "node:test";
import Ajv from "ajv/dist/2020.js";
import lodash from "lodash";
import express from "express";
import errs from "../lib/error.js";

// Load production modules while replacing only external effects (DB, network,
// certbot and filesystem writes). No production data or certificates are used.
async function loadModule(relativePath, imports, globals = {}, exportName = "default") {
	const url = new URL(relativePath, import.meta.url);
	const context = vm.createContext({ Buffer, URLSearchParams, FormData, Blob, Date, ...globals });
	const module = new vm.SourceTextModule(fs.readFileSync(url, "utf8"), {
		context,
		identifier: url.href,
		initializeImportMeta(meta) { meta.url = url.href; },
	});
	await module.link((specifier) => {
		const values = imports[specifier];
		assert.ok(values, `Unmocked import: ${specifier}`);
		return new vm.SyntheticModule(Object.keys(values), function () {
			for (const [name, value] of Object.entries(values)) this.setExport(name, value);
		}, { context });
	});
	await module.evaluate();
	return module.namespace[exportName];
}

const logger = { info() {}, success() {}, error() {}, warn() {}, debug() {} };
const queryReturning = (row) => {
	const query = { first: async () => row };
	for (const method of ["where", "andWhere", "allowGraph", "withGraphFetched"]) query[method] = () => query;
	return { query: () => query };
};

test("password change revokes old token as 401, fresh token retains permission checks", async () => {
	for (const issuedAt of [undefined, null, "100", Number.NaN, 100.5, 99, 100]) {
		const tokenData = { attrs: { id: 1 }, scope: ["user"], iat: issuedAt };
		const Access = await loadModule("../lib/access.js", {
			"node:fs": { default: fs },
			"node:path": { dirname: (path) => path.slice(0, path.lastIndexOf("/")) },
			"node:url": { fileURLToPath },
			"ajv/dist/2020.js": { default: Ajv },
			lodash: { default: lodash },
			"../logger.js": { access: logger },
			"../models/auth.js": { default: queryReturning({ meta: { password_changed_at: 100 } }) },
			"../models/proxy_host.js": { default: {} },
			"../models/token.js": { default: () => ({ load: async () => tokenData, get: (key) => tokenData[key], hasScope: () => true }) },
			"../models/user.js": { default: queryReturning({ id: 1, roles: ["admin"], permissions: { visibility: "all" } }) },
			"./access/permissions.json": { default: JSON.parse(fs.readFileSync(new URL("../lib/access/permissions.json", import.meta.url))) },
			"./access/roles.json": { default: JSON.parse(fs.readFileSync(new URL("../lib/access/roles.json", import.meta.url))) },
			"./error.js": { default: errs },
		});
		const access = new Access("fixture-token");
		if (!Number.isSafeInteger(issuedAt) || issuedAt < 100) await assert.rejects(access.can("users:list"), (err) => err instanceof errs.TokenRevokedError && err.status === 401);
		else assert.ok(await access.can("users:list"));
	}
});

test("password change rejects an old 2FA challenge before consuming a code, fresh challenge signs in", async () => {
	for (const issuedAt of [undefined, null, "100", Number.NaN, 100.5, 99, 100]) {
		let checkedCodes = 0;
		let createdTokens = 0;
		const token = await loadModule("../internal/token.js", {
			lodash: { default: lodash }, "../lib/error.js": { default: errs },
			"../lib/helpers.js": { parseDatePeriod: () => new Date("2099-01-01") },
			"../models/auth.js": { default: queryReturning({ meta: { password_changed_at: 100 } }) },
			"../models/token.js": { default: () => ({
				load: async () => ({ scope: ["2fa-challenge"], attrs: { id: 1 }, iat: issuedAt }),
				create: async () => { createdTokens++; return { token: "fresh fixture" }; },
			}) },
			"../models/user.js": { default: {} },
			"./2fa.js": { default: { verifyForLogin: async () => { checkedCodes++; return true; } } },
		});
		if (!Number.isSafeInteger(issuedAt) || issuedAt < 100) {
			await assert.rejects(token.verify2FA("challenge fixture", "123456"), (err) => err instanceof errs.TokenRevokedError && err.status === 401);
			assert.equal(checkedCodes, 0);
			assert.equal(createdTokens, 0);
		} else {
			assert.equal((await token.verify2FA("challenge fixture", "123456")).token, "fresh fixture");
			assert.equal(checkedCodes, 1);
			assert.equal(createdTokens, 1);
		}
	}
});

test("token refresh checks the current session before issuing a fresh token", async () => {
	let createdTokens = 0;
	const token = await loadModule("../internal/token.js", {
		lodash: { default: lodash }, "../lib/error.js": { default: errs },
		"../lib/helpers.js": { parseDatePeriod: () => new Date("2099-01-01") },
		"../models/auth.js": { default: {} },
		"../models/token.js": { default: () => ({ create: async () => { createdTokens++; return { token: "fresh fixture" }; } }) },
		"../models/user.js": { default: {} }, "./2fa.js": { default: {} },
	});
	for (const revoked of [true, false]) {
		const access = {
			token: { getUserId: () => 1, get: () => ["user"], hasScope: () => false },
			can: async (permission, id) => {
				assert.equal(permission, "users:get");
				assert.equal(id, 1);
				if (revoked) throw new errs.TokenRevokedError("Revoked fixture");
				return true;
			},
		};
		if (revoked) {
			await assert.rejects(token.getFreshToken(access, {}), (err) => err.status === 401);
			assert.equal(createdTokens, 0);
		} else {
			assert.equal((await token.getFreshToken(access, {})).token, "fresh fixture");
			assert.equal(createdTokens, 1);
		}
	}
});

test("Agent forwards path ACL payload and retries a revoked remote token once", async () => {
	const requests = [];
	let tokenCount = 0;
	const agent = { id: 7, enabled: true, url: "https://agent.invalid", identity: "fixture", secret: "fixture" };
	const client = await loadModule("../internal/agent-client.js", {
		"../lib/error.js": { default: errs },
		"../models/agent.js": { default: queryReturning(agent) },
	}, {
		fetch: async (url, options) => {
			requests.push({ url, ...options });
			if (url.endsWith("/api/tokens")) return new Response(JSON.stringify({ token: `token-${++tokenCount}`, expires: "2099-01-01" }), { headers: { "content-type": "application/json" } });
			return new Response(JSON.stringify({ id: 3 }), { status: tokenCount === 1 ? 401 : 200, headers: { "content-type": "application/json" } });
		},
	});
	const payload = { locations: [{ path: "/private", access_list_id: 12 }] };
	const req = { method: "PUT", baseUrl: "/nginx/proxy-hosts", path: "/3", query: { agent_id: "7", expand: "access_list" }, body: payload };
	const res = { status(code) { this.code = code; return this; }, set() {}, send(data) { this.data = data; } };
	await client.forward(req, res);
	assert.equal(tokenCount, 2);
	assert.equal(requests.length, 4);
	const forwards = requests.filter((r) => !r.url.endsWith("/api/tokens"));
	assert.equal(forwards[0].url, "https://agent.invalid/api/nginx/proxy-hosts/3?expand=access_list");
	assert.deepEqual(JSON.parse(forwards[0].body), payload);
	assert.equal(forwards[1].headers.Authorization, "Bearer token-2");
	assert.equal(res.code, 200);
});

test("Agent forwarding requires local admin permission before any network call", async () => {
	let forwarded = false;
	const middleware = await loadModule("../lib/express/agent-forward.js", {
		"../../internal/agent-client.js": { default: { shouldForward: () => true, forward: async () => { forwarded = true; } } },
		"../../logger.js": { debug() {}, express: logger },
	});
	let error;
	await middleware()({ method: "GET", originalUrl: "/api/nginx/proxy-hosts/3/logs?agent_id=7" }, { locals: { access: { can: async () => { throw new errs.PermissionError(); } } } }, (err) => { error = err; });
	assert.equal(error.status, 403);
	assert.equal(forwarded, false);
});

test("host log route forwards remote Agent before reading same-ID local logs", async () => {
	let localReads = 0;
	const forwarding = await loadModule("../lib/express/agent-forward.js", {
		"../../internal/agent-client.js": { default: {
			shouldForward: (req) => req.query.agent_id === "7",
			forward: async (_req, res) => { res.status(200).send({ logs: "remote fixture" }); },
		} },
		"../../logger.js": { debug() {}, express: logger },
	});
	const router = await loadModule("../routes/nginx/proxy_hosts.js", {
		express: { default: express },
		"../../internal/log-viewer.js": { readLastLines: async (_path, count) => { assert.equal(count, 1000); localReads++; return { lines: ["local fixture"] }; } },
		"../../internal/proxy-host.js": { default: {} },
		"../../lib/express/agent-forward.js": { default: forwarding },
		"../../lib/express/jwt-decode.js": { default: () => (_req, res, next) => { res.locals.access = { can: async () => true }; next(); } },
		"../../lib/validator/api.js": { default: async (_, data) => data },
		"../../lib/validator/index.js": { default: async (_, data) => data },
		"../../logger.js": { debug() {}, express: logger },
		"../../schema/index.js": { getValidationSchema: () => ({}) },
	});
	const app = express();
	app.use("/api/nginx/proxy-hosts", router);
	const server = app.listen(0, "127.0.0.1");
	await new Promise((resolve) => server.once("listening", resolve));
	try {
		const url = `http://127.0.0.1:${server.address().port}/api/nginx/proxy-hosts/3/logs`;
		assert.deepEqual(await (await fetch(`${url}?agent_id=7&type=access`)).json(), { logs: "remote fixture" });
		assert.equal(localReads, 0);
		assert.deepEqual(await (await fetch(`${url}?type=access`)).json(), { logs: "local fixture" });
		assert.equal(localReads, 1);
	} finally {
		await new Promise((resolve) => server.close(resolve));
	}
});

test("bounded log reader caps scanning a huge newline-free file at 5 MiB", async () => {
	let bytesRead = 0;
	let closed = false;
	const handle = {
		stat: async () => ({ size: 50 * 1024 * 1024 * 1024 }),
		read: async (buffer, _offset, length) => { bytesRead += length; buffer.fill(0x78); return { bytesRead: length }; },
		close: async () => { closed = true; },
	};
	const readLastLines = await loadModule("../internal/log-viewer.js", {
		"node:fs": { default: { promises: { open: async () => handle } } },
		"../lib/error.js": { default: errs },
		"./dead-host.js": { default: {} }, "./proxy-host.js": { default: {} },
		"./redirection-host.js": { default: {} }, "./stream.js": { default: {} },
	}, {}, "readLastLines");
	const result = await readLastLines("fixture.log", 1000);
	assert.equal(result.truncated, true);
	assert.equal(result.lines.length, 0);
	assert.ok(bytesRead <= 5 * 1024 * 1024 + 1);
	assert.ok(closed);
});

test("DNS reissue removes credential file after success and failure", async () => {
	for (const fails of [false, true]) {
		const calls = [];
		const imports = {
			"node:fs": { default: { mkdirSync() {}, writeFileSync(path, _value, options) { calls.push({ action: "write", path, mode: options.mode }); }, unlink(path) { calls.push({ action: "unlink", path }); } } },
			"node:https": { default: {} }, path: { default: {} }, archiver: { ZipArchive: class {} }, lodash: { default: lodash }, moment: { default: () => {} }, "proxy-agent": { ProxyAgent: class {} }, "temp-write": { default: {} },
			"../certbot/dns-plugins.json": { default: { fixture: { name: "Fixture DNS", full_plugin_name: "dns-fixture" } } },
			"../lib/certbot.js": { installPlugin: async () => {} },
			"../lib/config.js": { useLetsencryptServer: () => false, useLetsencryptStaging: () => false },
			"../lib/error.js": { default: errs },
			"../lib/utils.js": { default: { execFile: async () => { if (fails) throw new Error("certbot fixture failure"); return "issued"; } } },
			"../logger.js": { debug() {}, ssl: logger },
		};
		for (const name of ["certificate", "dead_host", "proxy_host", "redirection_host", "token", "user"]) imports[`../models/${name}.js`] = { default: {} };
		for (const name of ["audit-log", "host", "nginx"]) imports[`./${name}.js`] = { default: {} };
		const certificate = await loadModule("../internal/certificate.js", imports);
		certificate.getAdditionalCertbotArgs = () => ({ args: [], opts: {} });
		const result = certificate.reissueLetsEncryptSslWithDnsChallenge({ id: 9, domain_names: ["example.invalid"], meta: { dns_provider: "fixture", dns_provider_credentials: "fixture" } }, "fixture@example.invalid");
		if (fails) await assert.rejects(result, /certbot fixture failure/);
		else assert.equal(await result, "issued");
		assert.deepEqual(calls.map((call) => call.action), ["write", "unlink"]);
		assert.equal(calls[0].mode, 0o600);
		assert.equal(calls[0].path, calls[1].path);
	}
});
