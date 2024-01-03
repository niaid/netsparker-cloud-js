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
import type { FieldPairValue } from './FieldPairValue';
import type { IntegrationCustomFieldVm } from './IntegrationCustomFieldVm';
import type { IntegrationWizardResultModel } from './IntegrationWizardResultModel';
/**
 *
 * @export
 * @interface ServiceNowVRMModel
 */
export interface ServiceNowVRMModel {
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    username: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    url: string;
    /**
     * Gets web hook URL.
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly webhookUrl?: string;
    /**
     * Gets or sets the ServiceNow password for the user.
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    password: string;
    /**
     *
     * @type {{ [key: string]: FieldPairValue; }}
     * @memberof ServiceNowVRMModel
     */
    fieldPairs?: {
        [key: string]: FieldPairValue;
    };
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly resolvedStatus?: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly reopenStatus?: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly falsePositiveStatus?: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly acceptedRiskStatus?: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    summaryFormat: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    cIMatchingColumn?: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    cIMatchingColumnText?: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly type?: ServiceNowVRMModelTypeEnum;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly genericErrorMessage?: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly identifier?: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly testMessageBody?: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly testMessageTitle?: string;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    name?: string;
    /**
     *
     * @type {number}
     * @memberof ServiceNowVRMModel
     */
    integrationVersion?: number;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    accountID?: string;
    /**
     *
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof ServiceNowVRMModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    templateType?: ServiceNowVRMModelTemplateTypeEnum;
    /**
     *
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    titleFormat: string;
    /**
     *
     * @type {IntegrationWizardResultModel}
     * @memberof ServiceNowVRMModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}
/**
 * @export
 */
export declare const ServiceNowVRMModelTypeEnum: {
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
export type ServiceNowVRMModelTypeEnum = typeof ServiceNowVRMModelTypeEnum[keyof typeof ServiceNowVRMModelTypeEnum];
/**
 * @export
 */
export declare const ServiceNowVRMModelTemplateTypeEnum: {
    readonly Standard: "Standard";
    readonly Detailed: "Detailed";
};
export type ServiceNowVRMModelTemplateTypeEnum = typeof ServiceNowVRMModelTemplateTypeEnum[keyof typeof ServiceNowVRMModelTemplateTypeEnum];
/**
 * Check if a given object implements the ServiceNowVRMModel interface.
 */
export declare function instanceOfServiceNowVRMModel(value: object): boolean;
export declare function ServiceNowVRMModelFromJSON(json: any): ServiceNowVRMModel;
export declare function ServiceNowVRMModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ServiceNowVRMModel;
export declare function ServiceNowVRMModelToJSON(value?: ServiceNowVRMModel | null): any;
