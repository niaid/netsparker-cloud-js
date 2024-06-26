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
    /**
     *
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    id?: string;
    /**
     *
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    state?: AzureKeyVaultIntegrationInfoModelStateEnum;
}
/**
 * @export
 */
export declare const AzureKeyVaultIntegrationInfoModelAgentModeEnum: {
    readonly Cloud: "Cloud";
    readonly Internal: "Internal";
};
export type AzureKeyVaultIntegrationInfoModelAgentModeEnum = typeof AzureKeyVaultIntegrationInfoModelAgentModeEnum[keyof typeof AzureKeyVaultIntegrationInfoModelAgentModeEnum];
/**
 * @export
 */
export declare const AzureKeyVaultIntegrationInfoModelTypeEnum: {
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
export type AzureKeyVaultIntegrationInfoModelTypeEnum = typeof AzureKeyVaultIntegrationInfoModelTypeEnum[keyof typeof AzureKeyVaultIntegrationInfoModelTypeEnum];
/**
 * @export
 */
export declare const AzureKeyVaultIntegrationInfoModelTemplateTypeEnum: {
    readonly Standard: "Standard";
    readonly Detailed: "Detailed";
};
export type AzureKeyVaultIntegrationInfoModelTemplateTypeEnum = typeof AzureKeyVaultIntegrationInfoModelTemplateTypeEnum[keyof typeof AzureKeyVaultIntegrationInfoModelTemplateTypeEnum];
/**
 * @export
 */
export declare const AzureKeyVaultIntegrationInfoModelStateEnum: {
    readonly Active: "Active";
    readonly Suspended: "Suspended";
};
export type AzureKeyVaultIntegrationInfoModelStateEnum = typeof AzureKeyVaultIntegrationInfoModelStateEnum[keyof typeof AzureKeyVaultIntegrationInfoModelStateEnum];
/**
 * Check if a given object implements the AzureKeyVaultIntegrationInfoModel interface.
 */
export declare function instanceOfAzureKeyVaultIntegrationInfoModel(value: object): boolean;
export declare function AzureKeyVaultIntegrationInfoModelFromJSON(json: any): AzureKeyVaultIntegrationInfoModel;
export declare function AzureKeyVaultIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AzureKeyVaultIntegrationInfoModel;
export declare function AzureKeyVaultIntegrationInfoModelToJSON(value?: Omit<AzureKeyVaultIntegrationInfoModel, 'Type' | 'GenericErrorMessage' | 'Identifier' | 'TestMessageBody' | 'TestMessageTitle' | 'WebhookUrl'> | null): any;
