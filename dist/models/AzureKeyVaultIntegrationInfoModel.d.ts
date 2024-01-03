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
 * The Vault integration info
 * @export
 * @interface AzureKeyVaultIntegrationInfoModel
 */
export interface AzureKeyVaultIntegrationInfoModel {
    /**
     * ClientId for authentication.
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    clientID: string;
    /**
     * Secret for authentication.
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    secret: string;
    /**
     *
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    agentMode?: AzureKeyVaultIntegrationInfoModelAgentModeEnum;
    /**
     * The Vault instance tenantId.
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    tenantId: string;
    /**
     *
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    readonly type?: AzureKeyVaultIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     *
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    templateType?: AzureKeyVaultIntegrationInfoModelTemplateTypeEnum;
    /**
     *
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     *
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}
/**
* @export
* @enum {string}
*/
export declare enum AzureKeyVaultIntegrationInfoModelAgentModeEnum {
    Cloud = "Cloud",
    Internal = "Internal"
}
/**
* @export
* @enum {string}
*/
export declare enum AzureKeyVaultIntegrationInfoModelTypeEnum {
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
export declare enum AzureKeyVaultIntegrationInfoModelTemplateTypeEnum {
    Standard = "Standard",
    Detailed = "Detailed"
}
/**
 * Check if a given object implements the AzureKeyVaultIntegrationInfoModel interface.
 */
export declare function instanceOfAzureKeyVaultIntegrationInfoModel(value: object): boolean;
export declare function AzureKeyVaultIntegrationInfoModelFromJSON(json: any): AzureKeyVaultIntegrationInfoModel;
export declare function AzureKeyVaultIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AzureKeyVaultIntegrationInfoModel;
export declare function AzureKeyVaultIntegrationInfoModelToJSON(value?: AzureKeyVaultIntegrationInfoModel | null): any;
