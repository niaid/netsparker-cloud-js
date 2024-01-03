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
 * The Mattermost integration info
 * @export
 * @interface MattermostIntegrationInfoModel
 */
export interface MattermostIntegrationInfoModel {
    /**
     * Gets or sets the Webhook URL.
     * @type {string}
     * @memberof MattermostIntegrationInfoModel
     */
    incomingWebhookUrl: string;
    /**
     *
     * @type {string}
     * @memberof MattermostIntegrationInfoModel
     */
    readonly type?: MattermostIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof MattermostIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof MattermostIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof MattermostIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof MattermostIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof MattermostIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     *
     * @type {string}
     * @memberof MattermostIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof MattermostIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof MattermostIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof MattermostIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof MattermostIntegrationInfoModel
     */
    templateType?: MattermostIntegrationInfoModelTemplateTypeEnum;
    /**
     *
     * @type {string}
     * @memberof MattermostIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     *
     * @type {string}
     * @memberof MattermostIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof MattermostIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof MattermostIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}
/**
 * @export
 */
export declare const MattermostIntegrationInfoModelTypeEnum: {
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
export type MattermostIntegrationInfoModelTypeEnum = typeof MattermostIntegrationInfoModelTypeEnum[keyof typeof MattermostIntegrationInfoModelTypeEnum];
/**
 * @export
 */
export declare const MattermostIntegrationInfoModelTemplateTypeEnum: {
    readonly Standard: "Standard";
    readonly Detailed: "Detailed";
};
export type MattermostIntegrationInfoModelTemplateTypeEnum = typeof MattermostIntegrationInfoModelTemplateTypeEnum[keyof typeof MattermostIntegrationInfoModelTemplateTypeEnum];
/**
 * Check if a given object implements the MattermostIntegrationInfoModel interface.
 */
export declare function instanceOfMattermostIntegrationInfoModel(value: object): boolean;
export declare function MattermostIntegrationInfoModelFromJSON(json: any): MattermostIntegrationInfoModel;
export declare function MattermostIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): MattermostIntegrationInfoModel;
export declare function MattermostIntegrationInfoModelToJSON(value?: MattermostIntegrationInfoModel | null): any;
