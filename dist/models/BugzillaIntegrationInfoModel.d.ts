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
 * The Bugzilla integration info
 * @export
 * @interface BugzillaIntegrationInfoModel
 */
export interface BugzillaIntegrationInfoModel {
    /**
     * The Bugzilla instance URL.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    url: string;
    /**
     * API Key for authentication.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    apiKey: string;
    /**
     * The product name.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    product: string;
    /**
     * The name of a component.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    component: string;
    /**
     * The product version that the issue was found in.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    version: string;
    /**
     * What type of hardware the bug was experienced on.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    platform: string;
    /**
     * The operating system the bug was discovered on.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    operationSystem: string;
    /**
     * The status that this bug should start out as.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    status?: string;
    /**
     * The priority of the bug.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    priority?: string;
    /**
     * The user email adress to assign issues to.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    assignedTo?: string;
    /**
     * The serverity of the bug.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    severity?: string;
    /**
     * A valid target milestone for the product.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    milestone?: string;
    /**
     * The days when incident is due from the time that issue is created on.
     * @type {number}
     * @memberof BugzillaIntegrationInfoModel
     */
    dueDays?: number;
    /**
     *
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    readonly type?: BugzillaIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     *
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof BugzillaIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof BugzillaIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    templateType?: BugzillaIntegrationInfoModelTemplateTypeEnum;
    /**
     *
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     *
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof BugzillaIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}
/**
* @export
* @enum {string}
*/
export declare enum BugzillaIntegrationInfoModelTypeEnum {
    NetsparkerEnterprise = "NetsparkerEnterprise",
    Webhook = "Webhook",
    Zapier = "Zapier",
    Slack = "Slack",
    Mattermost = "Mattermost",
    MicrosoftTeams = "MicrosoftTeams",
    AzureDevOps = "AzureDevOps",
    Bitbucket = "Bitbucket",
    Bugzilla = "Bugzilla",
    Clubhouse = "Clubhouse",
    DefectDojo = "DefectDojo",
    PivotalTracker = "PivotalTracker",
    Jira = "Jira",
    FogBugz = "FogBugz",
    GitHub = "GitHub",
    PagerDuty = "PagerDuty",
    Kafka = "Kafka",
    Kenna = "Kenna",
    Redmine = "Redmine",
    ServiceNow = "ServiceNow",
    Tfs = "TFS",
    Unfuddle = "Unfuddle",
    YouTrack = "YouTrack",
    Freshservice = "Freshservice",
    Splunk = "Splunk",
    JazzTeam = "JazzTeam",
    ServiceNowVrm = "ServiceNowVRM",
    Asana = "Asana",
    Trello = "Trello",
    Hashicorp = "Hashicorp",
    CyberArk = "CyberArk",
    AzureKeyVault = "AzureKeyVault",
    GitLab = "GitLab"
}
/**
* @export
* @enum {string}
*/
export declare enum BugzillaIntegrationInfoModelTemplateTypeEnum {
    Standard = "Standard",
    Detailed = "Detailed"
}
/**
 * Check if a given object implements the BugzillaIntegrationInfoModel interface.
 */
export declare function instanceOfBugzillaIntegrationInfoModel(value: object): boolean;
export declare function BugzillaIntegrationInfoModelFromJSON(json: any): BugzillaIntegrationInfoModel;
export declare function BugzillaIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): BugzillaIntegrationInfoModel;
export declare function BugzillaIntegrationInfoModelToJSON(value?: BugzillaIntegrationInfoModel | null): any;
