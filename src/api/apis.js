"use strict";
function __export(m) {
    for (var p in m) if (!exports.hasOwnProperty(p)) exports[p] = m[p];
}
Object.defineProperty(exports, "__esModule", { value: true });
__export(require("./accountApi"));
const accountApi_1 = require("./accountApi");
__export(require("./agentGroupsApi"));
const agentGroupsApi_1 = require("./agentGroupsApi");
__export(require("./agentsApi"));
const agentsApi_1 = require("./agentsApi");
__export(require("./auditLogsApi"));
const auditLogsApi_1 = require("./auditLogsApi");
__export(require("./authenticationProfilesApi"));
const authenticationProfilesApi_1 = require("./authenticationProfilesApi");
__export(require("./discoveryApi"));
const discoveryApi_1 = require("./discoveryApi");
__export(require("./issuesApi"));
const issuesApi_1 = require("./issuesApi");
__export(require("./notificationsApi"));
const notificationsApi_1 = require("./notificationsApi");
__export(require("./scanPoliciesApi"));
const scanPoliciesApi_1 = require("./scanPoliciesApi");
__export(require("./scanProfilesApi"));
const scanProfilesApi_1 = require("./scanProfilesApi");
__export(require("./scansApi"));
const scansApi_1 = require("./scansApi");
__export(require("./teamMembersApi"));
const teamMembersApi_1 = require("./teamMembersApi");
__export(require("./technologiesApi"));
const technologiesApi_1 = require("./technologiesApi");
__export(require("./vulnerabilityApi"));
const vulnerabilityApi_1 = require("./vulnerabilityApi");
__export(require("./websiteGroupsApi"));
const websiteGroupsApi_1 = require("./websiteGroupsApi");
__export(require("./websitesApi"));
const websitesApi_1 = require("./websitesApi");
class HttpError extends Error {
    constructor(response, body, statusCode) {
        super('HTTP request failed');
        this.response = response;
        this.body = body;
        this.statusCode = statusCode;
        this.name = 'HttpError';
    }
}
exports.HttpError = HttpError;
exports.APIS = [accountApi_1.AccountApi, agentGroupsApi_1.AgentGroupsApi, agentsApi_1.AgentsApi, auditLogsApi_1.AuditLogsApi, authenticationProfilesApi_1.AuthenticationProfilesApi, discoveryApi_1.DiscoveryApi, issuesApi_1.IssuesApi, notificationsApi_1.NotificationsApi, scanPoliciesApi_1.ScanPoliciesApi, scanProfilesApi_1.ScanProfilesApi, scansApi_1.ScansApi, teamMembersApi_1.TeamMembersApi, technologiesApi_1.TechnologiesApi, vulnerabilityApi_1.VulnerabilityApi, websiteGroupsApi_1.WebsiteGroupsApi, websitesApi_1.WebsitesApi];
//# sourceMappingURL=apis.js.map