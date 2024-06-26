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
 *
 * @export
 * @interface CyberArkVaultIntegrationInfoModel
 */
export interface CyberArkVaultIntegrationInfoModel {
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    certificateFileKey?: string;
    /**
     * Pfx File Password for authentication.
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    certificateFilePassword?: string;
    /**
     * The Vault instance URL.
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    url: string;
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    agentMode?: CyberArkVaultIntegrationInfoModelAgentModeEnum;
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    readonly type?: CyberArkVaultIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    templateType?: CyberArkVaultIntegrationInfoModelTemplateTypeEnum;
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    id?: string;
    /**
     *
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    state?: CyberArkVaultIntegrationInfoModelStateEnum;
}
/**
 * @export
 */
export declare const CyberArkVaultIntegrationInfoModelAgentModeEnum: {
    readonly Cloud: "Cloud";
    readonly Internal: "Internal";
};
export type CyberArkVaultIntegrationInfoModelAgentModeEnum = typeof CyberArkVaultIntegrationInfoModelAgentModeEnum[keyof typeof CyberArkVaultIntegrationInfoModelAgentModeEnum];
/**
 * @export
 */
export declare const CyberArkVaultIntegrationInfoModelTypeEnum: {
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
export type CyberArkVaultIntegrationInfoModelTypeEnum = typeof CyberArkVaultIntegrationInfoModelTypeEnum[keyof typeof CyberArkVaultIntegrationInfoModelTypeEnum];
/**
 * @export
 */
export declare const CyberArkVaultIntegrationInfoModelTemplateTypeEnum: {
    readonly Standard: "Standard";
    readonly Detailed: "Detailed";
};
export type CyberArkVaultIntegrationInfoModelTemplateTypeEnum = typeof CyberArkVaultIntegrationInfoModelTemplateTypeEnum[keyof typeof CyberArkVaultIntegrationInfoModelTemplateTypeEnum];
/**
 * @export
 */
export declare const CyberArkVaultIntegrationInfoModelStateEnum: {
    readonly Active: "Active";
    readonly Suspended: "Suspended";
};
export type CyberArkVaultIntegrationInfoModelStateEnum = typeof CyberArkVaultIntegrationInfoModelStateEnum[keyof typeof CyberArkVaultIntegrationInfoModelStateEnum];
/**
 * Check if a given object implements the CyberArkVaultIntegrationInfoModel interface.
 */
export declare function instanceOfCyberArkVaultIntegrationInfoModel(value: object): boolean;
export declare function CyberArkVaultIntegrationInfoModelFromJSON(json: any): CyberArkVaultIntegrationInfoModel;
export declare function CyberArkVaultIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): CyberArkVaultIntegrationInfoModel;
export declare function CyberArkVaultIntegrationInfoModelToJSON(value?: Omit<CyberArkVaultIntegrationInfoModel, 'Type' | 'GenericErrorMessage' | 'Identifier' | 'TestMessageBody' | 'TestMessageTitle' | 'WebhookUrl'> | null): any;
