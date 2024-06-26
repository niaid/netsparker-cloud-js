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
import type { IntegrationWizardResultModel } from './IntegrationWizardResultModel';
import type { IntegrationCustomFieldVm } from './IntegrationCustomFieldVm';
/**
 * The GitLab integration info
 * @export
 * @interface GitLabIntegrationInfoModel
 */
export interface GitLabIntegrationInfoModel {
    /**
     * Gets or sets the access token.
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    accessToken: string;
    /**
     * Gets or sets the assignee id.
     * @type {number}
     * @memberof GitLabIntegrationInfoModel
     */
    assigneeId?: number;
    /**
     * Gets or sets the due days.
     * @type {number}
     * @memberof GitLabIntegrationInfoModel
     */
    dueDays?: number;
    /**
     * Gets or sets the labels.
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    labels?: string;
    /**
     * Gets or sets the milestone id.
     * @type {number}
     * @memberof GitLabIntegrationInfoModel
     */
    milestoneId?: number;
    /**
     * Gets or sets the on-premise base url.
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    onPremiseBaseURL?: string;
    /**
     * Gets or sets the project id.
     * @type {number}
     * @memberof GitLabIntegrationInfoModel
     */
    projectId: number;
    /**
     * Gets or sets the weight.
     * @type {number}
     * @memberof GitLabIntegrationInfoModel
     */
    weight?: number;
    /**
     *
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    readonly type?: GitLabIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     *
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof GitLabIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof GitLabIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    templateType?: GitLabIntegrationInfoModelTemplateTypeEnum;
    /**
     *
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     *
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof GitLabIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
    /**
     *
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    id?: string;
    /**
     *
     * @type {string}
     * @memberof GitLabIntegrationInfoModel
     */
    state?: GitLabIntegrationInfoModelStateEnum;
}
/**
 * @export
 */
export declare const GitLabIntegrationInfoModelTypeEnum: {
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
export type GitLabIntegrationInfoModelTypeEnum = typeof GitLabIntegrationInfoModelTypeEnum[keyof typeof GitLabIntegrationInfoModelTypeEnum];
/**
 * @export
 */
export declare const GitLabIntegrationInfoModelTemplateTypeEnum: {
    readonly Standard: "Standard";
    readonly Detailed: "Detailed";
};
export type GitLabIntegrationInfoModelTemplateTypeEnum = typeof GitLabIntegrationInfoModelTemplateTypeEnum[keyof typeof GitLabIntegrationInfoModelTemplateTypeEnum];
/**
 * @export
 */
export declare const GitLabIntegrationInfoModelStateEnum: {
    readonly Active: "Active";
    readonly Suspended: "Suspended";
};
export type GitLabIntegrationInfoModelStateEnum = typeof GitLabIntegrationInfoModelStateEnum[keyof typeof GitLabIntegrationInfoModelStateEnum];
/**
 * Check if a given object implements the GitLabIntegrationInfoModel interface.
 */
export declare function instanceOfGitLabIntegrationInfoModel(value: object): boolean;
export declare function GitLabIntegrationInfoModelFromJSON(json: any): GitLabIntegrationInfoModel;
export declare function GitLabIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): GitLabIntegrationInfoModel;
export declare function GitLabIntegrationInfoModelToJSON(value?: Omit<GitLabIntegrationInfoModel, 'Type' | 'GenericErrorMessage' | 'Identifier' | 'TestMessageBody' | 'TestMessageTitle' | 'WebhookUrl'> | null): any;
