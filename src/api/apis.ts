export * from './accountApi';
import { AccountApi } from './accountApi';
export * from './agentGroupsApi';
import { AgentGroupsApi } from './agentGroupsApi';
export * from './agentsApi';
import { AgentsApi } from './agentsApi';
export * from './auditLogsApi';
import { AuditLogsApi } from './auditLogsApi';
export * from './authenticationProfilesApi';
import { AuthenticationProfilesApi } from './authenticationProfilesApi';
export * from './discoveryApi';
import { DiscoveryApi } from './discoveryApi';
export * from './issuesApi';
import { IssuesApi } from './issuesApi';
export * from './membersApi';
import { MembersApi } from './membersApi';
export * from './notificationsApi';
import { NotificationsApi } from './notificationsApi';
export * from './rolesApi';
import { RolesApi } from './rolesApi';
export * from './scanPoliciesApi';
import { ScanPoliciesApi } from './scanPoliciesApi';
export * from './scanProfilesApi';
import { ScanProfilesApi } from './scanProfilesApi';
export * from './scansApi';
import { ScansApi } from './scansApi';
export * from './teamApi';
import { TeamApi } from './teamApi';
export * from './technologiesApi';
import { TechnologiesApi } from './technologiesApi';
export * from './vulnerabilityApi';
import { VulnerabilityApi } from './vulnerabilityApi';
export * from './websiteGroupsApi';
import { WebsiteGroupsApi } from './websiteGroupsApi';
export * from './websitesApi';
import { WebsitesApi } from './websitesApi';
import * as http from 'http';

export class HttpError extends Error {
    constructor (public response: http.IncomingMessage, public body: any, public statusCode?: number) {
        super('HTTP request failed');
        this.name = 'HttpError';
    }
}

export { RequestFile } from '../model/models';

export const APIS = [AccountApi, AgentGroupsApi, AgentsApi, AuditLogsApi, AuthenticationProfilesApi, DiscoveryApi, IssuesApi, MembersApi, NotificationsApi, RolesApi, ScanPoliciesApi, ScanProfilesApi, ScansApi, TeamApi, TechnologiesApi, VulnerabilityApi, WebsiteGroupsApi, WebsitesApi];
