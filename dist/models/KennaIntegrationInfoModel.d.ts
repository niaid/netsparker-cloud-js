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
 * The Kenna integration info
 * @export
 * @interface KennaIntegrationInfoModel
 */
export interface KennaIntegrationInfoModel {
    /**
     * The API key for API requests.
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    apiKey: string;
    /**
     * The API URL.
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    apiUrl: string;
    /**
     * The days when issue is due from the time that issue is created on.
     * @type {number}
     * @memberof KennaIntegrationInfoModel
     */
    dueDays: number;
    /**
     *
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    tags?: string;
    /**
     * Set Asset application identifier
     * @type {boolean}
     * @memberof KennaIntegrationInfoModel
     */
    setAssetApplicationIdentifier?: boolean;
    /**
     * Asset application identifier type
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    assetApplicationIdentifierType?: KennaIntegrationInfoModelAssetApplicationIdentifierTypeEnum;
    /**
     * The Instance URL.
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    instanceUrl: string;
    /**
     * Asset application identifier
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    assetApplicationIdentifier?: string;
    /**
     *
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    readonly type?: KennaIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     *
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof KennaIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof KennaIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    templateType?: KennaIntegrationInfoModelTemplateTypeEnum;
    /**
     *
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     *
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof KennaIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}
/**
 * @export
 */
export declare const KennaIntegrationInfoModelAssetApplicationIdentifierTypeEnum: {
    readonly WebsiteName: "WebsiteName";
    readonly Static: "Static";
};
export type KennaIntegrationInfoModelAssetApplicationIdentifierTypeEnum = typeof KennaIntegrationInfoModelAssetApplicationIdentifierTypeEnum[keyof typeof KennaIntegrationInfoModelAssetApplicationIdentifierTypeEnum];
/**
 * @export
 */
export declare const KennaIntegrationInfoModelTypeEnum: {
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
export type KennaIntegrationInfoModelTypeEnum = typeof KennaIntegrationInfoModelTypeEnum[keyof typeof KennaIntegrationInfoModelTypeEnum];
/**
 * @export
 */
export declare const KennaIntegrationInfoModelTemplateTypeEnum: {
    readonly Standard: "Standard";
    readonly Detailed: "Detailed";
};
export type KennaIntegrationInfoModelTemplateTypeEnum = typeof KennaIntegrationInfoModelTemplateTypeEnum[keyof typeof KennaIntegrationInfoModelTemplateTypeEnum];
/**
 * Check if a given object implements the KennaIntegrationInfoModel interface.
 */
export declare function instanceOfKennaIntegrationInfoModel(value: object): boolean;
export declare function KennaIntegrationInfoModelFromJSON(json: any): KennaIntegrationInfoModel;
export declare function KennaIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): KennaIntegrationInfoModel;
export declare function KennaIntegrationInfoModelToJSON(value?: KennaIntegrationInfoModel | null): any;