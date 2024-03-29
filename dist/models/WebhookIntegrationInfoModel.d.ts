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
import type { CustomHttpHeaderModel } from './CustomHttpHeaderModel';
import type { IntegrationCustomFieldVm } from './IntegrationCustomFieldVm';
import type { IntegrationWizardResultModel } from './IntegrationWizardResultModel';
/**
 * The Webhook integration info
 * @export
 * @interface WebhookIntegrationInfoModel
 */
export interface WebhookIntegrationInfoModel {
    /**
     * The HTTP method that indicates the action to be performed on a resource for the request.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    httpMethodType?: WebhookIntegrationInfoModelHttpMethodTypeEnum;
    /**
     * This is the data format in which requests are sent.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    parameterType?: WebhookIntegrationInfoModelParameterTypeEnum;
    /**
     * The URL to which issues should be sent.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    url: string;
    /**
     * The parameter name of the issue.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    issue?: string;
    /**
     * Gets or sets the Http Header.
     * @type {Array<CustomHttpHeaderModel>}
     * @memberof WebhookIntegrationInfoModel
     */
    customHttpHeaderModels?: Array<CustomHttpHeaderModel>;
    /**
     * The parameter name of the issue title.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    title?: string;
    /**
     * The parameter name of the issue body.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    body?: string;
    /**
     * The Username for the HTTP authentication.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    username?: string;
    /**
     * The Password for the HTTP authentication.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    password?: string;
    /**
     *
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    readonly type?: WebhookIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     *
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof WebhookIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof WebhookIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    templateType?: WebhookIntegrationInfoModelTemplateTypeEnum;
    /**
     *
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     *
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof WebhookIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}
/**
 * @export
 */
export declare const WebhookIntegrationInfoModelHttpMethodTypeEnum: {
    readonly Get: "Get";
    readonly Post: "Post";
    readonly Put: "Put";
};
export type WebhookIntegrationInfoModelHttpMethodTypeEnum = typeof WebhookIntegrationInfoModelHttpMethodTypeEnum[keyof typeof WebhookIntegrationInfoModelHttpMethodTypeEnum];
/**
 * @export
 */
export declare const WebhookIntegrationInfoModelParameterTypeEnum: {
    readonly Form: "Form";
    readonly Json: "Json";
    readonly Xml: "Xml";
    readonly QueryString: "QueryString";
};
export type WebhookIntegrationInfoModelParameterTypeEnum = typeof WebhookIntegrationInfoModelParameterTypeEnum[keyof typeof WebhookIntegrationInfoModelParameterTypeEnum];
/**
 * @export
 */
export declare const WebhookIntegrationInfoModelTypeEnum: {
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
export type WebhookIntegrationInfoModelTypeEnum = typeof WebhookIntegrationInfoModelTypeEnum[keyof typeof WebhookIntegrationInfoModelTypeEnum];
/**
 * @export
 */
export declare const WebhookIntegrationInfoModelTemplateTypeEnum: {
    readonly Standard: "Standard";
    readonly Detailed: "Detailed";
};
export type WebhookIntegrationInfoModelTemplateTypeEnum = typeof WebhookIntegrationInfoModelTemplateTypeEnum[keyof typeof WebhookIntegrationInfoModelTemplateTypeEnum];
/**
 * Check if a given object implements the WebhookIntegrationInfoModel interface.
 */
export declare function instanceOfWebhookIntegrationInfoModel(value: object): boolean;
export declare function WebhookIntegrationInfoModelFromJSON(json: any): WebhookIntegrationInfoModel;
export declare function WebhookIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): WebhookIntegrationInfoModel;
export declare function WebhookIntegrationInfoModelToJSON(value?: WebhookIntegrationInfoModel | null): any;
