/**
 * Invicti Enterprise API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: v1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
import * as runtime from '../runtime';
import type { AllIssuesApiModel, IssueApiResult, IssueApiUpdateModel, IssueSummaryApiResult, VulnerabilityContentApiModel } from '../models/index';
export interface IssuesAddressedIssuesRequest {
    severity?: IssuesAddressedIssuesSeverityEnum;
    webSiteName?: string;
    websiteGroupName?: string;
    page?: number;
    pageSize?: number;
}
export interface IssuesAllIssuesRequest {
    severity?: IssuesAllIssuesSeverityEnum;
    webSiteName?: string;
    websiteGroupName?: string;
    page?: number;
    pageSize?: number;
    sortType?: IssuesAllIssuesSortTypeEnum;
    lastSeenDate?: string;
    rawDetails?: boolean;
    integration?: IssuesAllIssuesIntegrationEnum;
}
export interface IssuesGetRequest {
    id: string;
}
export interface IssuesGetVulnerabilityContentRequest {
    id: string;
}
export interface IssuesReportRequest {
    csvSeparator?: IssuesReportCsvSeparatorEnum;
    severity?: IssuesReportSeverityEnum;
    websiteGroupName?: string;
    webSiteName?: string;
    startDate?: Date;
    endDate?: Date;
}
export interface IssuesSummaryRequest {
    targetUri: string;
    websiteRoot: string;
    sinceDate?: string;
    scanTaskGroupId?: string;
    page?: number;
    pageSize?: number;
}
export interface IssuesTodoRequest {
    severity?: IssuesTodoSeverityEnum;
    webSiteName?: string;
    websiteGroupName?: string;
    page?: number;
    pageSize?: number;
}
export interface IssuesUpdateRequest {
    model: IssueApiUpdateModel;
}
export interface IssuesWaitingForRetestRequest {
    severity?: IssuesWaitingForRetestSeverityEnum;
    webSiteName?: string;
    websiteGroupName?: string;
    page?: number;
    pageSize?: number;
}
/**
 *
 */
export declare class IssuesApi extends runtime.BaseAPI {
    /**
     * Gets the list of addressed issues.
     */
    issuesAddressedIssuesRaw(requestParameters: IssuesAddressedIssuesRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<IssueApiResult>>;
    /**
     * Gets the list of addressed issues.
     */
    issuesAddressedIssues(requestParameters?: IssuesAddressedIssuesRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<IssueApiResult>;
    /**
     * Gets the list of all issues.
     */
    issuesAllIssuesRaw(requestParameters: IssuesAllIssuesRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<IssueApiResult>>;
    /**
     * Gets the list of all issues.
     */
    issuesAllIssues(requestParameters?: IssuesAllIssuesRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<IssueApiResult>;
    /**
     * Gets issues by id. Returns with encoded(raw html) vulnerability template data by default.
     */
    issuesGetRaw(requestParameters: IssuesGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<AllIssuesApiModel>>;
    /**
     * Gets issues by id. Returns with encoded(raw html) vulnerability template data by default.
     */
    issuesGet(requestParameters: IssuesGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<AllIssuesApiModel>;
    /**
     * Gets vulnerability request/response content by id.
     */
    issuesGetVulnerabilityContentRaw(requestParameters: IssuesGetVulnerabilityContentRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<VulnerabilityContentApiModel>>;
    /**
     * Gets vulnerability request/response content by id.
     */
    issuesGetVulnerabilityContent(requestParameters: IssuesGetVulnerabilityContentRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<VulnerabilityContentApiModel>;
    /**
     * Generates a report of issues in the CSV format.
     */
    issuesReportRaw(requestParameters: IssuesReportRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>>;
    /**
     * Generates a report of issues in the CSV format.
     */
    issuesReport(requestParameters?: IssuesReportRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void>;
    /**
     * Gets the summary of vulnerabilities
     */
    issuesSummaryRaw(requestParameters: IssuesSummaryRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<IssueSummaryApiResult>>;
    /**
     * Gets the summary of vulnerabilities
     */
    issuesSummary(requestParameters: IssuesSummaryRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<IssueSummaryApiResult>;
    /**
     * Gets the list of to-do issues.
     */
    issuesTodoRaw(requestParameters: IssuesTodoRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<IssueApiResult>>;
    /**
     * Gets the list of to-do issues.
     */
    issuesTodo(requestParameters?: IssuesTodoRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<IssueApiResult>;
    /**
     * Updates an existing issue.
     */
    issuesUpdateRaw(requestParameters: IssuesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>>;
    /**
     * Updates an existing issue.
     */
    issuesUpdate(requestParameters: IssuesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void>;
    /**
     * Gets the list of retest issues.
     */
    issuesWaitingForRetestRaw(requestParameters: IssuesWaitingForRetestRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<IssueApiResult>>;
    /**
     * Gets the list of retest issues.
     */
    issuesWaitingForRetest(requestParameters?: IssuesWaitingForRetestRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<IssueApiResult>;
}
/**
 * @export
 */
export declare const IssuesAddressedIssuesSeverityEnum: {
    readonly BestPractice: "BestPractice";
    readonly Information: "Information";
    readonly Low: "Low";
    readonly Medium: "Medium";
    readonly High: "High";
    readonly Critical: "Critical";
};
export type IssuesAddressedIssuesSeverityEnum = typeof IssuesAddressedIssuesSeverityEnum[keyof typeof IssuesAddressedIssuesSeverityEnum];
/**
 * @export
 */
export declare const IssuesAllIssuesSeverityEnum: {
    readonly BestPractice: "BestPractice";
    readonly Information: "Information";
    readonly Low: "Low";
    readonly Medium: "Medium";
    readonly High: "High";
    readonly Critical: "Critical";
};
export type IssuesAllIssuesSeverityEnum = typeof IssuesAllIssuesSeverityEnum[keyof typeof IssuesAllIssuesSeverityEnum];
/**
 * @export
 */
export declare const IssuesAllIssuesSortTypeEnum: {
    readonly Ascending: "Ascending";
    readonly Descending: "Descending";
};
export type IssuesAllIssuesSortTypeEnum = typeof IssuesAllIssuesSortTypeEnum[keyof typeof IssuesAllIssuesSortTypeEnum];
/**
 * @export
 */
export declare const IssuesAllIssuesIntegrationEnum: {
    readonly Jira: "Jira";
    readonly GitHub: "GitHub";
    readonly Tfs: "TFS";
    readonly FogBugz: "FogBugz";
    readonly ServiceNow: "ServiceNow";
    readonly Slack: "Slack";
    readonly GitLab: "GitLab";
    readonly Bitbucket: "Bitbucket";
    readonly Unfuddle: "Unfuddle";
    readonly Zapier: "Zapier";
    readonly AzureDevOps: "AzureDevOps";
    readonly Redmine: "Redmine";
    readonly Bugzilla: "Bugzilla";
    readonly Kafka: "Kafka";
    readonly PagerDuty: "PagerDuty";
    readonly MicrosoftTeams: "MicrosoftTeams";
    readonly Clubhouse: "Clubhouse";
    readonly Trello: "Trello";
    readonly Asana: "Asana";
    readonly Webhook: "Webhook";
    readonly Kenna: "Kenna";
    readonly Freshservice: "Freshservice";
    readonly YouTrack: "YouTrack";
    readonly NetsparkerEnterprise: "NetsparkerEnterprise";
    readonly Splunk: "Splunk";
    readonly Mattermost: "Mattermost";
    readonly Hashicorp: "Hashicorp";
    readonly PivotalTracker: "PivotalTracker";
    readonly CyberArk: "CyberArk";
    readonly DefectDojo: "DefectDojo";
    readonly JazzTeam: "JazzTeam";
    readonly AzureKeyVault: "AzureKeyVault";
    readonly ServiceNowVrm: "ServiceNowVRM";
};
export type IssuesAllIssuesIntegrationEnum = typeof IssuesAllIssuesIntegrationEnum[keyof typeof IssuesAllIssuesIntegrationEnum];
/**
 * @export
 */
export declare const IssuesReportCsvSeparatorEnum: {
    readonly Comma: "Comma";
    readonly Semicolon: "Semicolon";
    readonly Pipe: "Pipe";
    readonly Tab: "Tab";
};
export type IssuesReportCsvSeparatorEnum = typeof IssuesReportCsvSeparatorEnum[keyof typeof IssuesReportCsvSeparatorEnum];
/**
 * @export
 */
export declare const IssuesReportSeverityEnum: {
    readonly BestPractice: "BestPractice";
    readonly Information: "Information";
    readonly Low: "Low";
    readonly Medium: "Medium";
    readonly High: "High";
    readonly Critical: "Critical";
};
export type IssuesReportSeverityEnum = typeof IssuesReportSeverityEnum[keyof typeof IssuesReportSeverityEnum];
/**
 * @export
 */
export declare const IssuesTodoSeverityEnum: {
    readonly BestPractice: "BestPractice";
    readonly Information: "Information";
    readonly Low: "Low";
    readonly Medium: "Medium";
    readonly High: "High";
    readonly Critical: "Critical";
};
export type IssuesTodoSeverityEnum = typeof IssuesTodoSeverityEnum[keyof typeof IssuesTodoSeverityEnum];
/**
 * @export
 */
export declare const IssuesWaitingForRetestSeverityEnum: {
    readonly BestPractice: "BestPractice";
    readonly Information: "Information";
    readonly Low: "Low";
    readonly Medium: "Medium";
    readonly High: "High";
    readonly Critical: "Critical";
};
export type IssuesWaitingForRetestSeverityEnum = typeof IssuesWaitingForRetestSeverityEnum[keyof typeof IssuesWaitingForRetestSeverityEnum];