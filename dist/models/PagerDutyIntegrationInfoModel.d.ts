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
 * The PagerDuty integration info
 * @export
 * @interface PagerDutyIntegrationInfoModel
 */
export interface PagerDutyIntegrationInfoModel {
    /**
     * API Access Key for authentication.
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    apiAccessKey: string;
    /**
     * The PagerDuty instance URL.
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    readonly apiUrl?: string;
    /**
     * The incident will be created on this service type.
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    bodyDetails?: string;
    /**
     * The email address of a valid user associated with the account making the request.
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    from: string;
    /**
     * Type must be incident_body.
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    readonly incidentBodyType?: string;
    /**
     * Type must be incident.
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    readonly incidentType?: string;
    /**
     * The incident will be created on this service id.
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    serviceId: string;
    /**
     * The incident will be created on this service type.
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    serviceType: PagerDutyIntegrationInfoModelServiceTypeEnum;
    /**
     * A succinct description of the nature, symptoms, cause, or effect of the incident.
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    title?: string;
    /**
     * The urgency of the incident.
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    urgency?: PagerDutyIntegrationInfoModelUrgencyEnum;
    /**
     * The PagerDuty instance URL.
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    url: string;
    /**
     *
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    readonly type?: PagerDutyIntegrationInfoModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     *
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof PagerDutyIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof PagerDutyIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    templateType?: PagerDutyIntegrationInfoModelTemplateTypeEnum;
    /**
     *
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     *
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof PagerDutyIntegrationInfoModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof PagerDutyIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}
/**
 * @export
 */
export declare const PagerDutyIntegrationInfoModelServiceTypeEnum: {
    readonly Service: "service";
    readonly ServiceReference: "service_reference";
};
export type PagerDutyIntegrationInfoModelServiceTypeEnum = typeof PagerDutyIntegrationInfoModelServiceTypeEnum[keyof typeof PagerDutyIntegrationInfoModelServiceTypeEnum];
/**
 * @export
 */
export declare const PagerDutyIntegrationInfoModelUrgencyEnum: {
    readonly High: "high";
    readonly Low: "low";
};
export type PagerDutyIntegrationInfoModelUrgencyEnum = typeof PagerDutyIntegrationInfoModelUrgencyEnum[keyof typeof PagerDutyIntegrationInfoModelUrgencyEnum];
/**
 * @export
 */
export declare const PagerDutyIntegrationInfoModelTypeEnum: {
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
export type PagerDutyIntegrationInfoModelTypeEnum = typeof PagerDutyIntegrationInfoModelTypeEnum[keyof typeof PagerDutyIntegrationInfoModelTypeEnum];
/**
 * @export
 */
export declare const PagerDutyIntegrationInfoModelTemplateTypeEnum: {
    readonly Standard: "Standard";
    readonly Detailed: "Detailed";
};
export type PagerDutyIntegrationInfoModelTemplateTypeEnum = typeof PagerDutyIntegrationInfoModelTemplateTypeEnum[keyof typeof PagerDutyIntegrationInfoModelTemplateTypeEnum];
/**
 * Check if a given object implements the PagerDutyIntegrationInfoModel interface.
 */
export declare function instanceOfPagerDutyIntegrationInfoModel(value: object): boolean;
export declare function PagerDutyIntegrationInfoModelFromJSON(json: any): PagerDutyIntegrationInfoModel;
export declare function PagerDutyIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): PagerDutyIntegrationInfoModel;
export declare function PagerDutyIntegrationInfoModelToJSON(value?: PagerDutyIntegrationInfoModel | null): any;
