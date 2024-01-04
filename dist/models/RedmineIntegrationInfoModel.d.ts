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
import type { IntegrationCustomFieldVm } from './IntegrationCustomFieldVm';
import type { IntegrationWizardResultModel } from './IntegrationWizardResultModel';
/**
 * The Redmine integration info
 * @export
 * @interface RedmineIntegrationInfoModel
 */
export interface RedmineIntegrationInfoModel {
    /**
     * The Redmine instance URL.
     * @type {string}
     * @memberof RedmineIntegrationInfoModel
     */
    url: string;
    /**
     * API Access Key for authentication.
     * @type {string}
     * @memberof RedmineIntegrationInfoModel
     */
    apiAccessKey: string;
    /**
     * The project identifer to create issue in.
     * @type {string}
     * @memberof RedmineIntegrationInfoModel
     */
    project: string;
    /**
     * The priority identifier.
     * @type {number}
     * @memberof RedmineIntegrationInfoModel
     */
    priorityId: number;
    /**
     * The tracker identifier.
     * @type {number}
     * @memberof RedmineIntegrationInfoModel
     */
    trackerId?: number;
    /**
     * The status identifier.
     * @type {number}
     * @memberof RedmineIntegrationInfoModel
     */
    statusId?: number;
    /**
     * The category identifier.
     * @type {number}
     * @memberof RedmineIntegrationInfoModel
     */
    categoryId?: number;
    /**
     * The user identifier to assign issues to.
     * @type {number}
     * @memberof RedmineIntegrationInfoModel
     */
    assignedTo?: number;
    /**
     * The days when incident is due from the time that issue created on.
     * @type {number}
     * @memberof RedmineIntegrationInfoModel
     */
    dueDays?: number;
    /**
     * The privacy information whether the issue is private.
     * @type {boolean}
     * @memberof RedmineIntegrationInfoModel
     */
    isPrivate?: boolean;
    /**
     *
     * @type {string}
     * @memberof RedmineIntegrationInfoModel
     */
    readonly type?: RedmineIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof RedmineIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof RedmineIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof RedmineIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof RedmineIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof RedmineIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     *
     * @type {string}
     * @memberof RedmineIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof RedmineIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof RedmineIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof RedmineIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof RedmineIntegrationInfoModel
     */
    templateType?: RedmineIntegrationInfoModelTemplateTypeEnum;
    /**
     *
     * @type {string}
     * @memberof RedmineIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     *
     * @type {string}
     * @memberof RedmineIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof RedmineIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof RedmineIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}
/**
 * @export
 */
export declare const RedmineIntegrationInfoModelTypeEnum: {
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
export type RedmineIntegrationInfoModelTypeEnum = typeof RedmineIntegrationInfoModelTypeEnum[keyof typeof RedmineIntegrationInfoModelTypeEnum];
/**
 * @export
 */
export declare const RedmineIntegrationInfoModelTemplateTypeEnum: {
    readonly Standard: "Standard";
    readonly Detailed: "Detailed";
};
export type RedmineIntegrationInfoModelTemplateTypeEnum = typeof RedmineIntegrationInfoModelTemplateTypeEnum[keyof typeof RedmineIntegrationInfoModelTemplateTypeEnum];
/**
 * Check if a given object implements the RedmineIntegrationInfoModel interface.
 */
export declare function instanceOfRedmineIntegrationInfoModel(value: object): boolean;
export declare function RedmineIntegrationInfoModelFromJSON(json: any): RedmineIntegrationInfoModel;
export declare function RedmineIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): RedmineIntegrationInfoModel;
export declare function RedmineIntegrationInfoModelToJSON(value?: RedmineIntegrationInfoModel | null): any;
