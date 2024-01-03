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
import type { ServiceNowIncidentFieldPairValue } from './ServiceNowIncidentFieldPairValue';
import type { ServiceNowIncidentMapping } from './ServiceNowIncidentMapping';
import type { ServiceNowIntegrationInfoModelFieldMappingsDictionary } from './ServiceNowIntegrationInfoModelFieldMappingsDictionary';
/**
 * The ServiceNow integration info
 * @export
 * @interface ServiceNowIntegrationInfoModel
 */
export interface ServiceNowIntegrationInfoModel {
    /**
     * Gets or sets the assigned to ID.
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    assignedToId?: string;
    /**
     * Gets or sets the caller ID.
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    callerId?: string;
    /**
     * Gets or sets the category to assign cases to.
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    serviceNowCategoryTypes?: ServiceNowIntegrationInfoModelServiceNowCategoryTypesEnum;
    /**
     * Gets or sets the category to assign cases to.
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    categoryTypes?: string;
    /**
     * Gets or sets the type of the issue.
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    readonly reopenStatus?: string;
    /**
     * Gets or sets the category types
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    serviceNowReopenCategoryType?: ServiceNowIntegrationInfoModelServiceNowReopenCategoryTypeEnum;
    /**
     * Gets or sets the category types
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    serviceNowOnHoldReasonType?: ServiceNowIntegrationInfoModelServiceNowOnHoldReasonTypeEnum;
    /**
     * if this option selected , after retesting change the status of fixed vulnerabilities to Closed..
     * @type {boolean}
     * @memberof ServiceNowIntegrationInfoModel
     */
    closeTheFixedVulnerabilities?: boolean;
    /**
     * Gets or sets the category to assign cases to.
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    category?: string;
    /**
     * Gets or sets the due date.
     * @type {number}
     * @memberof ServiceNowIntegrationInfoModel
     */
    dueDays?: number;
    /**
     * The severity of the incident.
     * @type {number}
     * @memberof ServiceNowIntegrationInfoModel
     */
    severity?: number;
    /**
     * Gets or sets the ServiceNow password for the user.
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    password: string;
    /**
     * Gets or sets the type of the issue. Need to be overriden for webhooks supported integrations
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    readonly resolvedStatus?: string;
    /**
     * Gets or sets the ServiceNow resolved type of the issue.
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    resolvedStatusServiceNow?: ServiceNowIntegrationInfoModelResolvedStatusServiceNowEnum;
    /**
     * Gets or sets the URL.
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    url: string;
    /**
     * Gets FogBugz web hook URL.
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * Gets or sets the username.
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    username: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    templateType?: ServiceNowIntegrationInfoModelTemplateTypeEnum;
    /**
     *
     * @type {ServiceNowIntegrationInfoModelFieldMappingsDictionary}
     * @memberof ServiceNowIntegrationInfoModel
     */
    fieldMappingsDictionary?: ServiceNowIntegrationInfoModelFieldMappingsDictionary;
    /**
     * Returns ServiceNow incident field pairs.
     * @type {{ [key: string]: ServiceNowIncidentFieldPairValue; }}
     * @memberof ServiceNowIntegrationInfoModel
     */
    incidentFieldPairs?: {
        [key: string]: ServiceNowIncidentFieldPairValue;
    };
    /**
     * Returns whether servicenow integration is created with improved version .
     * @type {boolean}
     * @memberof ServiceNowIntegrationInfoModel
     */
    isImprovedVersion?: boolean;
    /**
     * Returns ServiceNow incident field mappings.
     * @type {Array<ServiceNowIncidentMapping>}
     * @memberof ServiceNowIntegrationInfoModel
     */
    fieldMappings?: Array<ServiceNowIncidentMapping>;
    /**
     *
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    readonly type?: ServiceNowIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof ServiceNowIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof ServiceNowIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof ServiceNowIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof ServiceNowIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}
/**
* @export
* @enum {string}
*/
export declare enum ServiceNowIntegrationInfoModelServiceNowCategoryTypesEnum {
    Inquiry = "Inquiry",
    Software = "Software",
    Hardware = "Hardware",
    Network = "Network",
    Database = "Database"
}
/**
* @export
* @enum {string}
*/
export declare enum ServiceNowIntegrationInfoModelServiceNowReopenCategoryTypeEnum {
    New = "New",
    InProgress = "In_Progress",
    OnHold = "On_Hold"
}
/**
* @export
* @enum {string}
*/
export declare enum ServiceNowIntegrationInfoModelServiceNowOnHoldReasonTypeEnum {
    AwaitingCaller = "AwaitingCaller",
    AwaitingChange = "AwaitingChange",
    AwaitingProblem = "AwaitingProblem",
    AwaitingVendor = "AwaitingVendor"
}
/**
* @export
* @enum {string}
*/
export declare enum ServiceNowIntegrationInfoModelResolvedStatusServiceNowEnum {
    Resolved = "Resolved",
    Closed = "Closed"
}
/**
* @export
* @enum {string}
*/
export declare enum ServiceNowIntegrationInfoModelTemplateTypeEnum {
    Standard = "Standard",
    Detailed = "Detailed"
}
/**
* @export
* @enum {string}
*/
export declare enum ServiceNowIntegrationInfoModelTypeEnum {
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
 * Check if a given object implements the ServiceNowIntegrationInfoModel interface.
 */
export declare function instanceOfServiceNowIntegrationInfoModel(value: object): boolean;
export declare function ServiceNowIntegrationInfoModelFromJSON(json: any): ServiceNowIntegrationInfoModel;
export declare function ServiceNowIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ServiceNowIntegrationInfoModel;
export declare function ServiceNowIntegrationInfoModelToJSON(value?: ServiceNowIntegrationInfoModel | null): any;
