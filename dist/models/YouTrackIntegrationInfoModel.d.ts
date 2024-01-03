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
