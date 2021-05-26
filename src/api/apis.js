"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.APIS = exports.HttpError = void 0;
__exportStar(require("./accountApi"), exports);
const accountApi_1 = require("./accountApi");
__exportStar(require("./agentGroupsApi"), exports);
const agentGroupsApi_1 = require("./agentGroupsApi");
__exportStar(require("./agentsApi"), exports);
const agentsApi_1 = require("./agentsApi");
__exportStar(require("./auditLogsApi"), exports);
const auditLogsApi_1 = require("./auditLogsApi");
__exportStar(require("./authenticationProfilesApi"), exports);
const authenticationProfilesApi_1 = require("./authenticationProfilesApi");
__exportStar(require("./discoveryApi"), exports);
const discoveryApi_1 = require("./discoveryApi");
__exportStar(require("./issuesApi"), exports);
const issuesApi_1 = require("./issuesApi");
__exportStar(require("./notificationsApi"), exports);
const notificationsApi_1 = require("./notificationsApi");
__exportStar(require("./scanPoliciesApi"), exports);
const scanPoliciesApi_1 = require("./scanPoliciesApi");
__exportStar(require("./scanProfilesApi"), exports);
const scanProfilesApi_1 = require("./scanProfilesApi");
__exportStar(require("./scansApi"), exports);
const scansApi_1 = require("./scansApi");
__exportStar(require("./teamMembersApi"), exports);
const teamMembersApi_1 = require("./teamMembersApi");
__exportStar(require("./technologiesApi"), exports);
const technologiesApi_1 = require("./technologiesApi");
__exportStar(require("./vulnerabilityApi"), exports);
const vulnerabilityApi_1 = require("./vulnerabilityApi");
__exportStar(require("./websiteGroupsApi"), exports);
const websiteGroupsApi_1 = require("./websiteGroupsApi");
__exportStar(require("./websitesApi"), exports);
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