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
 * The FogBugz integration info
 * @export
 * @interface FogBugzIntegrationInfoModel
 */
export interface FogBugzIntegrationInfoModel {
    /**
     * Gets or sets the area to assign cases to.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    area?: string;
    /**
     * Gets or sets the assigned to.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    assignedTo?: string;
    /**
     * Gets or sets the category to assign cases to.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    category: string;
    /**
     * Gets or sets the milestone to assign cases to.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    milestone?: string;
    /**
     * Gets or sets the project to assign cases to.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    project?: string;
    /**
     * Gets or sets the tags.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    tags?: string;
    /**
     * Gets or sets the FogBugz API token for the user.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    token: string;
    /**
     * Gets or sets the URL.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    url: string;
    /**
     * Gets FogBugz web hook URL.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     *
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    readonly type?: FogBugzIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof FogBugzIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof FogBugzIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    templateType?: FogBugzIntegrationInfoModelTemplateTypeEnum;
    /**
     *
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     *
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof FogBugzIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}
/**
* @export
* @enum {string}
*/
export declare enum FogBugzIntegrationInfoModelTypeEnum {
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
export declare enum FogBugzIntegrationInfoModelTemplateTypeEnum {
    Standard = "Standard",
    Detailed = "Detailed"
}
/**
 * Check if a given object implements the FogBugzIntegrationInfoModel interface.
 */
export declare function instanceOfFogBugzIntegrationInfoModel(value: object): boolean;
export declare function FogBugzIntegrationInfoModelFromJSON(json: any): FogBugzIntegrationInfoModel;
export declare function FogBugzIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): FogBugzIntegrationInfoModel;
export declare function FogBugzIntegrationInfoModelToJSON(value?: FogBugzIntegrationInfoModel | null): any;
