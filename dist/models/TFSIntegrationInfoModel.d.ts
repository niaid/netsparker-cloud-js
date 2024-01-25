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
 * The TFS integration info
 * @export
 * @interface TFSIntegrationInfoModel
 */
export interface TFSIntegrationInfoModel {
    /**
     * Gets or sets the assigned to.
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    assignedTo?: string;
    /**
     * Gets or sets the domain.
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    domain?: string;
    /**
     * Gets or sets the password.
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    password: string;
    /**
     * Gets or sets the project uri.
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    projectUri: string;
    /**
     * Gets or sets the tags.
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    tags?: string;
    /**
     * Gets or sets the username.
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    username: string;
    /**
     * Gets or sets the type of the work item type name.
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    workItemTypeName: string;
    /**
     *
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    readonly type?: TFSIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     *
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof TFSIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof TFSIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    templateType?: TFSIntegrationInfoModelTemplateTypeEnum;
    /**
     *
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     *
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof TFSIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof TFSIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}
/**
 * @export
 */
export declare const TFSIntegrationInfoModelTypeEnum: {
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
export type TFSIntegrationInfoModelTypeEnum = typeof TFSIntegrationInfoModelTypeEnum[keyof typeof TFSIntegrationInfoModelTypeEnum];
/**
 * @export
 */
export declare const TFSIntegrationInfoModelTemplateTypeEnum: {
    readonly Standard: "Standard";
    readonly Detailed: "Detailed";
};
export type TFSIntegrationInfoModelTemplateTypeEnum = typeof TFSIntegrationInfoModelTemplateTypeEnum[keyof typeof TFSIntegrationInfoModelTemplateTypeEnum];
/**
 * Check if a given object implements the TFSIntegrationInfoModel interface.
 */
export declare function instanceOfTFSIntegrationInfoModel(value: object): boolean;
export declare function TFSIntegrationInfoModelFromJSON(json: any): TFSIntegrationInfoModel;
export declare function TFSIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): TFSIntegrationInfoModel;
export declare function TFSIntegrationInfoModelToJSON(value?: TFSIntegrationInfoModel | null): any;
