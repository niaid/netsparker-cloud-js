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
 * The DefectDojo integration info
 * @export
 * @interface DefectDojoIntegrationInfoModel
 */
export interface DefectDojoIntegrationInfoModel {
    /**
     * Gets or sets the access token.
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    accessToken: string;
    /**
     * The Server URL.
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    serverUrl: string;
    /**
     * Gets or sets the labels.
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    tags?: string;
    /**
     * Gets or sets the repository.
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    engagementId: string;
    /**
     * Gets or sets the environment.
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    environment?: string;
    /**
     *
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    readonly type?: DefectDojoIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     *
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof DefectDojoIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof DefectDojoIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    templateType?: DefectDojoIntegrationInfoModelTemplateTypeEnum;
    /**
     *
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     *
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof DefectDojoIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
    /**
     *
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    id?: string;
    /**
     *
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    state?: DefectDojoIntegrationInfoModelStateEnum;
}
/**
 * @export
 */
export declare const DefectDojoIntegrationInfoModelTypeEnum: {
    readonly NetsparkerEnterprise: "NetsparkerEnterprise";
    readonly Webhook: "Webhook";
    readonly Zapier: "Zapier";
    readonly Slack: "Slack";
    readonly Mattermost: "Mattermost";
    readonly MicrosoftTeams: "MicrosoftTeams";
    readonly AzureDevOps: "AzureDevOps";
    readonly Bitbucket: "Bitbucket";
    readonly Bugzilla: "Bugzilla";
    readonly Clubhouse: "Clubhouse";
    readonly DefectDojo: "DefectDojo";
    readonly PivotalTracker: "PivotalTracker";
    readonly Jira: "Jira";
    readonly FogBugz: "FogBugz";
    readonly GitHub: "GitHub";
    readonly PagerDuty: "PagerDuty";
    readonly Kafka: "Kafka";
    readonly Kenna: "Kenna";
    readonly Redmine: "Redmine";
    readonly ServiceNow: "ServiceNow";
    readonly Tfs: "TFS";
    readonly Unfuddle: "Unfuddle";
    readonly YouTrack: "YouTrack";
    readonly Freshservice: "Freshservice";
    readonly Splunk: "Splunk";
    readonly JazzTeam: "JazzTeam";
    readonly ServiceNowVrm: "ServiceNowVRM";
    readonly Asana: "Asana";
    readonly Trello: "Trello";
    readonly Hashicorp: "Hashicorp";
    readonly CyberArk: "CyberArk";
    readonly AzureKeyVault: "AzureKeyVault";
    readonly GitLab: "GitLab";
};
export type DefectDojoIntegrationInfoModelTypeEnum = typeof DefectDojoIntegrationInfoModelTypeEnum[keyof typeof DefectDojoIntegrationInfoModelTypeEnum];
/**
 * @export
 */
export declare const DefectDojoIntegrationInfoModelTemplateTypeEnum: {
    readonly Standard: "Standard";
    readonly Detailed: "Detailed";
};
export type DefectDojoIntegrationInfoModelTemplateTypeEnum = typeof DefectDojoIntegrationInfoModelTemplateTypeEnum[keyof typeof DefectDojoIntegrationInfoModelTemplateTypeEnum];
/**
 * @export
 */
export declare const DefectDojoIntegrationInfoModelStateEnum: {
    readonly Active: "Active";
    readonly Suspended: "Suspended";
};
export type DefectDojoIntegrationInfoModelStateEnum = typeof DefectDojoIntegrationInfoModelStateEnum[keyof typeof DefectDojoIntegrationInfoModelStateEnum];
/**
 * Check if a given object implements the DefectDojoIntegrationInfoModel interface.
 */
export declare function instanceOfDefectDojoIntegrationInfoModel(value: object): boolean;
export declare function DefectDojoIntegrationInfoModelFromJSON(json: any): DefectDojoIntegrationInfoModel;
export declare function DefectDojoIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): DefectDojoIntegrationInfoModel;
export declare function DefectDojoIntegrationInfoModelToJSON(value?: Omit<DefectDojoIntegrationInfoModel, 'Type' | 'GenericErrorMessage' | 'Identifier' | 'TestMessageBody' | 'TestMessageTitle' | 'WebhookUrl'> | null): any;
