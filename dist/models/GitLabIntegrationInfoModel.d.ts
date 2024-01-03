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
}
/**
* @export
* @enum {string}
*/
export declare enum GitLabIntegrationInfoModelTypeEnum {
    Jira = "Jira",
    GitHub = "GitHub",
    Tfs = "TFS",
    FogBugz = "FogBugz",
    ServiceNow = "ServiceNow",
    Slack = "Slack",
    GitLab = "GitLab",
    Bitbucket = "Bitbucket",
    Unfuddle = "Unfuddle",
    Zapier = "Zapier",
    AzureDevOps = "AzureDevOps",
    Redmine = "Redmine",
    Bugzilla = "Bugzilla",
    Kafka = "Kafka",
    PagerDuty = "PagerDuty",
    MicrosoftTeams = "MicrosoftTeams",
    Clubhouse = "Clubhouse",
    Trello = "Trello",
    Asana = "Asana",
    Webhook = "Webhook",
    Kenna = "Kenna",
    Freshservice = "Freshservice",
    YouTrack = "YouTrack",
    NetsparkerEnterprise = "NetsparkerEnterprise",
    Splunk = "Splunk",
    Mattermost = "Mattermost",
    Hashicorp = "Hashicorp",
    PivotalTracker = "PivotalTracker",
    CyberArk = "CyberArk",
    DefectDojo = "DefectDojo",
    JazzTeam = "JazzTeam",
    AzureKeyVault = "AzureKeyVault",
    ServiceNowVrm = "ServiceNowVRM"
}
/**
* @export
* @enum {string}
*/
export declare enum GitLabIntegrationInfoModelTemplateTypeEnum {
    Standard = "Standard",
    Detailed = "Detailed"
}
/**
 * Check if a given object implements the GitLabIntegrationInfoModel interface.
 */
export declare function instanceOfGitLabIntegrationInfoModel(value: object): boolean;
export declare function GitLabIntegrationInfoModelFromJSON(json: any): GitLabIntegrationInfoModel;
export declare function GitLabIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): GitLabIntegrationInfoModel;
export declare function GitLabIntegrationInfoModelToJSON(value?: GitLabIntegrationInfoModel | null): any;
