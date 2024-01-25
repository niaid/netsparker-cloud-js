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
 * The YouTrack integration info
 * @export
 * @interface YouTrackIntegrationInfoModel
 */
export interface YouTrackIntegrationInfoModel {
    /**
     * The Server URL to send issues to.
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    serverUrl: string;
    /**
     * The bearer token.
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    token: string;
    /**
     * The project identifier.
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    projectId: string;
    /**
     * The tags. To add more than one tag, separate each one with a semicolon (;). For example : tag1;tag2
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    tags?: string;
    /**
     *
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    readonly type?: YouTrackIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     *
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof YouTrackIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof YouTrackIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    templateType?: YouTrackIntegrationInfoModelTemplateTypeEnum;
    /**
     *
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     *
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof YouTrackIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof YouTrackIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}
/**
 * @export
 */
export declare const YouTrackIntegrationInfoModelTypeEnum: {
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
export type YouTrackIntegrationInfoModelTypeEnum = typeof YouTrackIntegrationInfoModelTypeEnum[keyof typeof YouTrackIntegrationInfoModelTypeEnum];
/**
 * @export
 */
export declare const YouTrackIntegrationInfoModelTemplateTypeEnum: {
    readonly Standard: "Standard";
    readonly Detailed: "Detailed";
};
export type YouTrackIntegrationInfoModelTemplateTypeEnum = typeof YouTrackIntegrationInfoModelTemplateTypeEnum[keyof typeof YouTrackIntegrationInfoModelTemplateTypeEnum];
/**
 * Check if a given object implements the YouTrackIntegrationInfoModel interface.
 */
export declare function instanceOfYouTrackIntegrationInfoModel(value: object): boolean;
export declare function YouTrackIntegrationInfoModelFromJSON(json: any): YouTrackIntegrationInfoModel;
export declare function YouTrackIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): YouTrackIntegrationInfoModel;
export declare function YouTrackIntegrationInfoModelToJSON(value?: YouTrackIntegrationInfoModel | null): any;
