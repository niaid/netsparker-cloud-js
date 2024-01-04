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
import type { IntegrationUserMappingItemModel } from './IntegrationUserMappingItemModel';
import type { IntegrationWizardResultModel } from './IntegrationWizardResultModel';
import type { JiraPriorityMapping } from './JiraPriorityMapping';
/**
 * The Jira integration info
 * @export
 * @interface JiraIntegrationInfoModel
 */
export interface JiraIntegrationInfoModel {
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    assignedTo?: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    assignedToName?: string;
    /**
     *
     * @type {boolean}
     * @memberof JiraIntegrationInfoModel
     */
    autoAssignToPerson?: boolean;
    /**
     *
     * @type {number}
     * @memberof JiraIntegrationInfoModel
     */
    dueDays?: number;
    /**
     *
     * @type {boolean}
     * @memberof JiraIntegrationInfoModel
     */
    readonly isCloud?: boolean;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    issueType: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    issueTypeId?: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    labels?: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    components?: string;
    /**
     *
     * @type {Array<IntegrationUserMappingItemModel>}
     * @memberof JiraIntegrationInfoModel
     */
    mappedJiraUsers?: Array<IntegrationUserMappingItemModel>;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    password: string;
    /**
     * Gets or sets the priority.
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    priority?: string;
    /**
     * The issue security level.
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    securityLevel?: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    projectKey: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    projectName?: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    projectId?: string;
    /**
     * Gets or sets the type of the issue.
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly reopenStatus?: string;
    /**
     * Gets or sets the jira reopen type of the issue.
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    reopenStatusJira?: JiraIntegrationInfoModelReopenStatusJiraEnum;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    reporter?: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    reporterName?: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    url: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    usernameOrEmail: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    templateType?: JiraIntegrationInfoModelTemplateTypeEnum;
    /**
     * Gets or sets type of the jira epic name
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    epicName?: string;
    /**
     * Gets or sets type of the jira epic name custom field name
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    epicNameCustomFieldName?: string;
    /**
     * Gets or sets type of the jira epic key
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    epicKey?: string;
    /**
     * Gets or sets type of the jira epic key custom field name
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    epicKeyCustomFieldName?: string;
    /**
     * Gets or sets type of the jira epic type
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly epicSelectionType?: JiraIntegrationInfoModelEpicSelectionTypeEnum;
    /**
     *
     * @type {Array<JiraPriorityMapping>}
     * @memberof JiraIntegrationInfoModel
     */
    priorityMappings?: Array<JiraPriorityMapping>;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly type?: JiraIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof JiraIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof JiraIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof JiraIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}
/**
 * @export
 */
export declare const JiraIntegrationInfoModelReopenStatusJiraEnum: {
    readonly ToDo: "ToDo";
    readonly InProgress: "InProgress";
};
export type JiraIntegrationInfoModelReopenStatusJiraEnum = typeof JiraIntegrationInfoModelReopenStatusJiraEnum[keyof typeof JiraIntegrationInfoModelReopenStatusJiraEnum];
/**
 * @export
 */
export declare const JiraIntegrationInfoModelTemplateTypeEnum: {
    readonly Standard: "Standard";
    readonly Detailed: "Detailed";
};
export type JiraIntegrationInfoModelTemplateTypeEnum = typeof JiraIntegrationInfoModelTemplateTypeEnum[keyof typeof JiraIntegrationInfoModelTemplateTypeEnum];
/**
 * @export
 */
export declare const JiraIntegrationInfoModelEpicSelectionTypeEnum: {
    readonly None: "None";
    readonly EpicName: "EpicName";
    readonly EpicKey: "EpicKey";
};
export type JiraIntegrationInfoModelEpicSelectionTypeEnum = typeof JiraIntegrationInfoModelEpicSelectionTypeEnum[keyof typeof JiraIntegrationInfoModelEpicSelectionTypeEnum];
/**
 * @export
 */
export declare const JiraIntegrationInfoModelTypeEnum: {
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
export type JiraIntegrationInfoModelTypeEnum = typeof JiraIntegrationInfoModelTypeEnum[keyof typeof JiraIntegrationInfoModelTypeEnum];
/**
 * Check if a given object implements the JiraIntegrationInfoModel interface.
 */
export declare function instanceOfJiraIntegrationInfoModel(value: object): boolean;
export declare function JiraIntegrationInfoModelFromJSON(json: any): JiraIntegrationInfoModel;
export declare function JiraIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): JiraIntegrationInfoModel;
export declare function JiraIntegrationInfoModelToJSON(value?: JiraIntegrationInfoModel | null): any;
