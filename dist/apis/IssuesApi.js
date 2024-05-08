"use strict";
/* tslint:disable */
/* eslint-disable */
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.IssuesWaitingForRetestSeverityEnum = exports.IssuesTodoSeverityEnum = exports.IssuesReportSeverityEnum = exports.IssuesReportCsvSeparatorEnum = exports.IssuesAllIssuesIntegrationEnum = exports.IssuesAllIssuesSortTypeEnum = exports.IssuesAllIssuesSeverityEnum = exports.IssuesAddressedIssuesSeverityEnum = exports.IssuesApi = void 0;
const runtime = __importStar(require("../runtime"));
const index_1 = require("../models/index");
/**
 *
 */
class IssuesApi extends runtime.BaseAPI {
    /**
     * Gets the list of addressed issues.
     */
    async issuesAddressedIssuesRaw(requestParameters, initOverrides) {
        const queryParameters = {};
        if (requestParameters['severity'] != null) {
            queryParameters['severity'] = requestParameters['severity'];
        }
        if (requestParameters['webSiteName'] != null) {
            queryParameters['webSiteName'] = requestParameters['webSiteName'];
        }
        if (requestParameters['websiteGroupName'] != null) {
            queryParameters['websiteGroupName'] = requestParameters['websiteGroupName'];
        }
        if (requestParameters['page'] != null) {
            queryParameters['page'] = requestParameters['page'];
        }
        if (requestParameters['pageSize'] != null) {
            queryParameters['pageSize'] = requestParameters['pageSize'];
        }
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/issues/addressedissues`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => (0, index_1.IssueApiResultFromJSON)(jsonValue));
    }
    /**
     * Gets the list of addressed issues.
     */
    async issuesAddressedIssues(requestParameters = {}, initOverrides) {
        const response = await this.issuesAddressedIssuesRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Gets the list of all issues.
     */
    async issuesAllIssuesRaw(requestParameters, initOverrides) {
        const queryParameters = {};
        if (requestParameters['severity'] != null) {
            queryParameters['severity'] = requestParameters['severity'];
        }
        if (requestParameters['webSiteName'] != null) {
            queryParameters['webSiteName'] = requestParameters['webSiteName'];
        }
        if (requestParameters['websiteGroupName'] != null) {
            queryParameters['websiteGroupName'] = requestParameters['websiteGroupName'];
        }
        if (requestParameters['page'] != null) {
            queryParameters['page'] = requestParameters['page'];
        }
        if (requestParameters['pageSize'] != null) {
            queryParameters['pageSize'] = requestParameters['pageSize'];
        }
        if (requestParameters['sortType'] != null) {
            queryParameters['sortType'] = requestParameters['sortType'];
        }
        if (requestParameters['lastSeenDate'] != null) {
            queryParameters['lastSeenDate'] = requestParameters['lastSeenDate'];
        }
        if (requestParameters['rawDetails'] != null) {
            queryParameters['rawDetails'] = requestParameters['rawDetails'];
        }
        if (requestParameters['integration'] != null) {
            queryParameters['integration'] = requestParameters['integration'];
        }
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/issues/allissues`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => (0, index_1.IssueApiResultFromJSON)(jsonValue));
    }
    /**
     * Gets the list of all issues.
     */
    async issuesAllIssues(requestParameters = {}, initOverrides) {
        const response = await this.issuesAllIssuesRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Gets issues by id. Returns with encoded(raw html) vulnerability template data by default.
     */
    async issuesGetRaw(requestParameters, initOverrides) {
        if (requestParameters['id'] == null) {
            throw new runtime.RequiredError('id', 'Required parameter "id" was null or undefined when calling issuesGet().');
        }
        const queryParameters = {};
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/issues/get/{id}`.replace(`{${"id"}}`, encodeURIComponent(String(requestParameters['id']))),
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => (0, index_1.AllIssuesApiModelFromJSON)(jsonValue));
    }
    /**
     * Gets issues by id. Returns with encoded(raw html) vulnerability template data by default.
     */
    async issuesGet(requestParameters, initOverrides) {
        const response = await this.issuesGetRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Gets vulnerability request/response content by id.
     */
    async issuesGetVulnerabilityContentRaw(requestParameters, initOverrides) {
        if (requestParameters['id'] == null) {
            throw new runtime.RequiredError('id', 'Required parameter "id" was null or undefined when calling issuesGetVulnerabilityContent().');
        }
        const queryParameters = {};
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/issues/getvulnerabilitycontent/{id}`.replace(`{${"id"}}`, encodeURIComponent(String(requestParameters['id']))),
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => (0, index_1.VulnerabilityContentApiModelFromJSON)(jsonValue));
    }
    /**
     * Gets vulnerability request/response content by id.
     */
    async issuesGetVulnerabilityContent(requestParameters, initOverrides) {
        const response = await this.issuesGetVulnerabilityContentRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Generates a report of issues in the CSV format.
     */
    async issuesReportRaw(requestParameters, initOverrides) {
        const queryParameters = {};
        if (requestParameters['csvSeparator'] != null) {
            queryParameters['csvSeparator'] = requestParameters['csvSeparator'];
        }
        if (requestParameters['severity'] != null) {
            queryParameters['severity'] = requestParameters['severity'];
        }
        if (requestParameters['websiteGroupName'] != null) {
            queryParameters['websiteGroupName'] = requestParameters['websiteGroupName'];
        }
        if (requestParameters['webSiteName'] != null) {
            queryParameters['webSiteName'] = requestParameters['webSiteName'];
        }
        if (requestParameters['startDate'] != null) {
            queryParameters['startDate'] = requestParameters['startDate'].toISOString();
        }
        if (requestParameters['endDate'] != null) {
            queryParameters['endDate'] = requestParameters['endDate'].toISOString();
        }
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/issues/report`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.VoidApiResponse(response);
    }
    /**
     * Generates a report of issues in the CSV format.
     */
    async issuesReport(requestParameters = {}, initOverrides) {
        await this.issuesReportRaw(requestParameters, initOverrides);
    }
    /**
     * Gets the summary of vulnerabilities
     */
    async issuesSummaryRaw(requestParameters, initOverrides) {
        if (requestParameters['targetUri'] == null) {
            throw new runtime.RequiredError('targetUri', 'Required parameter "targetUri" was null or undefined when calling issuesSummary().');
        }
        if (requestParameters['websiteRoot'] == null) {
            throw new runtime.RequiredError('websiteRoot', 'Required parameter "websiteRoot" was null or undefined when calling issuesSummary().');
        }
        const queryParameters = {};
        if (requestParameters['targetUri'] != null) {
            queryParameters['targetUri'] = requestParameters['targetUri'];
        }
        if (requestParameters['websiteRoot'] != null) {
            queryParameters['websiteRoot'] = requestParameters['websiteRoot'];
        }
        if (requestParameters['sinceDate'] != null) {
            queryParameters['sinceDate'] = requestParameters['sinceDate'];
        }
        if (requestParameters['scanTaskGroupId'] != null) {
            queryParameters['scanTaskGroupId'] = requestParameters['scanTaskGroupId'];
        }
        if (requestParameters['page'] != null) {
            queryParameters['page'] = requestParameters['page'];
        }
        if (requestParameters['pageSize'] != null) {
            queryParameters['pageSize'] = requestParameters['pageSize'];
        }
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/issues/summary`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => (0, index_1.IssueSummaryApiResultFromJSON)(jsonValue));
    }
    /**
     * Gets the summary of vulnerabilities
     */
    async issuesSummary(requestParameters, initOverrides) {
        const response = await this.issuesSummaryRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Gets the list of to-do issues.
     */
    async issuesTodoRaw(requestParameters, initOverrides) {
        const queryParameters = {};
        if (requestParameters['severity'] != null) {
            queryParameters['severity'] = requestParameters['severity'];
        }
        if (requestParameters['webSiteName'] != null) {
            queryParameters['webSiteName'] = requestParameters['webSiteName'];
        }
        if (requestParameters['websiteGroupName'] != null) {
            queryParameters['websiteGroupName'] = requestParameters['websiteGroupName'];
        }
        if (requestParameters['page'] != null) {
            queryParameters['page'] = requestParameters['page'];
        }
        if (requestParameters['pageSize'] != null) {
            queryParameters['pageSize'] = requestParameters['pageSize'];
        }
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/issues/todo`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => (0, index_1.IssueApiResultFromJSON)(jsonValue));
    }
    /**
     * Gets the list of to-do issues.
     */
    async issuesTodo(requestParameters = {}, initOverrides) {
        const response = await this.issuesTodoRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Updates an existing issue.
     */
    async issuesUpdateRaw(requestParameters, initOverrides) {
        if (requestParameters['model'] == null) {
            throw new runtime.RequiredError('model', 'Required parameter "model" was null or undefined when calling issuesUpdate().');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/issues/update`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: (0, index_1.IssueApiUpdateModelToJSON)(requestParameters['model']),
        }, initOverrides);
        return new runtime.VoidApiResponse(response);
    }
    /**
     * Updates an existing issue.
     */
    async issuesUpdate(requestParameters, initOverrides) {
        await this.issuesUpdateRaw(requestParameters, initOverrides);
    }
    /**
     */
    async issuesWaitingForRetestRaw(requestParameters, initOverrides) {
        const queryParameters = {};
        if (requestParameters['severity'] != null) {
            queryParameters['severity'] = requestParameters['severity'];
        }
        if (requestParameters['webSiteName'] != null) {
            queryParameters['webSiteName'] = requestParameters['webSiteName'];
        }
        if (requestParameters['websiteGroupName'] != null) {
            queryParameters['websiteGroupName'] = requestParameters['websiteGroupName'];
        }
        if (requestParameters['page'] != null) {
            queryParameters['page'] = requestParameters['page'];
        }
        if (requestParameters['pageSize'] != null) {
            queryParameters['pageSize'] = requestParameters['pageSize'];
        }
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/issues/waitingforretest`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => (0, index_1.IssueApiResultFromJSON)(jsonValue));
    }
    /**
     */
    async issuesWaitingForRetest(requestParameters = {}, initOverrides) {
        const response = await this.issuesWaitingForRetestRaw(requestParameters, initOverrides);
        return await response.value();
    }
}
exports.IssuesApi = IssuesApi;
/**
 * @export
 */
exports.IssuesAddressedIssuesSeverityEnum = {
    BestPractice: 'BestPractice',
    Information: 'Information',
    Low: 'Low',
    Medium: 'Medium',
    High: 'High',
    Critical: 'Critical'
};
/**
 * @export
 */
exports.IssuesAllIssuesSeverityEnum = {
    BestPractice: 'BestPractice',
    Information: 'Information',
    Low: 'Low',
    Medium: 'Medium',
    High: 'High',
    Critical: 'Critical'
};
/**
 * @export
 */
exports.IssuesAllIssuesSortTypeEnum = {
    Ascending: 'Ascending',
    Descending: 'Descending'
};
/**
 * @export
 */
exports.IssuesAllIssuesIntegrationEnum = {
    Jira: 'Jira',
    GitHub: 'GitHub',
    Tfs: 'TFS',
    FogBugz: 'FogBugz',
    ServiceNow: 'ServiceNow',
    Slack: 'Slack',
    GitLab: 'GitLab',
    Bitbucket: 'Bitbucket',
    Unfuddle: 'Unfuddle',
    Zapier: 'Zapier',
    AzureDevOps: 'AzureDevOps',
    Redmine: 'Redmine',
    Bugzilla: 'Bugzilla',
    Kafka: 'Kafka',
    PagerDuty: 'PagerDuty',
    MicrosoftTeams: 'MicrosoftTeams',
    Clubhouse: 'Clubhouse',
    Trello: 'Trello',
    Asana: 'Asana',
    Webhook: 'Webhook',
    Kenna: 'Kenna',
    Freshservice: 'Freshservice',
    YouTrack: 'YouTrack',
    NetsparkerEnterprise: 'NetsparkerEnterprise',
    Splunk: 'Splunk',
    Mattermost: 'Mattermost',
    Hashicorp: 'Hashicorp',
    PivotalTracker: 'PivotalTracker',
    CyberArk: 'CyberArk',
    DefectDojo: 'DefectDojo',
    JazzTeam: 'JazzTeam',
    AzureKeyVault: 'AzureKeyVault',
    ServiceNowVrm: 'ServiceNowVRM'
};
/**
 * @export
 */
exports.IssuesReportCsvSeparatorEnum = {
    Comma: 'Comma',
    Semicolon: 'Semicolon',
    Pipe: 'Pipe',
    Tab: 'Tab'
};
/**
 * @export
 */
exports.IssuesReportSeverityEnum = {
    BestPractice: 'BestPractice',
    Information: 'Information',
    Low: 'Low',
    Medium: 'Medium',
    High: 'High',
    Critical: 'Critical'
};
/**
 * @export
 */
exports.IssuesTodoSeverityEnum = {
    BestPractice: 'BestPractice',
    Information: 'Information',
    Low: 'Low',
    Medium: 'Medium',
    High: 'High',
    Critical: 'Critical'
};
/**
 * @export
 */
exports.IssuesWaitingForRetestSeverityEnum = {
    BestPractice: 'BestPractice',
    Information: 'Information',
    Low: 'Low',
    Medium: 'Medium',
    High: 'High',
    Critical: 'Critical'
};
//# sourceMappingURL=IssuesApi.js.map