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
 * The Clubhouse integration info
 * @export
 * @interface ClubhouseIntegrationInfoModel
 */
export interface ClubhouseIntegrationInfoModel {
    /**
     * Api Token
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    apiToken: string;
    /**
     * The ID of the project to which the issue belongs.
     * @type {number}
     * @memberof ClubhouseIntegrationInfoModel
     */
    projectId: number;
    /**
     * Gets or sets the Clubhouse story type of the issue.
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    clubhouseStoryType?: ClubhouseIntegrationInfoModelClubhouseStoryTypeEnum;
    /**
     * The Epic Id identifier.
     * @type {number}
     * @memberof ClubhouseIntegrationInfoModel
     */
    epicId?: number;
    /**
     * The workflow state identifier that the Story is in.
     * @type {number}
     * @memberof ClubhouseIntegrationInfoModel
     */
    stateId?: number;
    /**
     * The member identifier of the person who requested the issue.
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    requesterId?: string;
    /**
     * Comma-separated member identifiers of those who own the issue.
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    ownerIds?: string;
    /**
     * Comma-separated member identifiers of those who follow the issue.
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    followerIds?: string;
    /**
     * The days when incident is due from the time that issue is created on.
     * @type {number}
     * @memberof ClubhouseIntegrationInfoModel
     */
    dueDays: number;
    /**
     * Comma-separated labels.
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    labels?: string;
    /**
     *
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    readonly type?: ClubhouseIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     *
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof ClubhouseIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof ClubhouseIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    templateType?: ClubhouseIntegrationInfoModelTemplateTypeEnum;
    /**
     *
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     *
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof ClubhouseIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
    /**
     *
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    id?: string;
    /**
     *
     * @type {string}
     * @memberof ClubhouseIntegrationInfoModel
     */
    state?: ClubhouseIntegrationInfoModelStateEnum;
}
/**
 * @export
 */
export declare const ClubhouseIntegrationInfoModelClubhouseStoryTypeEnum: {
    readonly Bug: "Bug";
    readonly Feature: "Feature";
    readonly Chore: "Chore";
};
export type ClubhouseIntegrationInfoModelClubhouseStoryTypeEnum = typeof ClubhouseIntegrationInfoModelClubhouseStoryTypeEnum[keyof typeof ClubhouseIntegrationInfoModelClubhouseStoryTypeEnum];
/**
 * @export
 */
export declare const ClubhouseIntegrationInfoModelTypeEnum: {
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
export type ClubhouseIntegrationInfoModelTypeEnum = typeof ClubhouseIntegrationInfoModelTypeEnum[keyof typeof ClubhouseIntegrationInfoModelTypeEnum];
/**
 * @export
 */
export declare const ClubhouseIntegrationInfoModelTemplateTypeEnum: {
    readonly Standard: "Standard";
    readonly Detailed: "Detailed";
};
export type ClubhouseIntegrationInfoModelTemplateTypeEnum = typeof ClubhouseIntegrationInfoModelTemplateTypeEnum[keyof typeof ClubhouseIntegrationInfoModelTemplateTypeEnum];
/**
 * @export
 */
export declare const ClubhouseIntegrationInfoModelStateEnum: {
    readonly Active: "Active";
    readonly Suspended: "Suspended";
};
export type ClubhouseIntegrationInfoModelStateEnum = typeof ClubhouseIntegrationInfoModelStateEnum[keyof typeof ClubhouseIntegrationInfoModelStateEnum];
/**
 * Check if a given object implements the ClubhouseIntegrationInfoModel interface.
 */
export declare function instanceOfClubhouseIntegrationInfoModel(value: object): boolean;
export declare function ClubhouseIntegrationInfoModelFromJSON(json: any): ClubhouseIntegrationInfoModel;
export declare function ClubhouseIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ClubhouseIntegrationInfoModel;
export declare function ClubhouseIntegrationInfoModelToJSON(value?: Omit<ClubhouseIntegrationInfoModel, 'Type' | 'GenericErrorMessage' | 'Identifier' | 'TestMessageBody' | 'TestMessageTitle' | 'WebhookUrl'> | null): any;
