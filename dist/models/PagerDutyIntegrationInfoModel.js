"use strict";
/* tslint:disable */
/* eslint-disable */
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.PagerDutyIntegrationInfoModelToJSON = exports.PagerDutyIntegrationInfoModelFromJSONTyped = exports.PagerDutyIntegrationInfoModelFromJSON = exports.instanceOfPagerDutyIntegrationInfoModel = exports.PagerDutyIntegrationInfoModelTemplateTypeEnum = exports.PagerDutyIntegrationInfoModelTypeEnum = exports.PagerDutyIntegrationInfoModelUrgencyEnum = exports.PagerDutyIntegrationInfoModelServiceTypeEnum = void 0;
const runtime_1 = require("../runtime");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
/**
 * @export
 */
exports.PagerDutyIntegrationInfoModelServiceTypeEnum = {
    Service: 'service',
    ServiceReference: 'service_reference'
};
/**
 * @export
 */
exports.PagerDutyIntegrationInfoModelUrgencyEnum = {
    High: 'high',
    Low: 'low'
};
/**
 * @export
 */
exports.PagerDutyIntegrationInfoModelTypeEnum = {
    Jira: 'Jira',
    GitHub: 'GitHub',
    Tfs: 'TFS',
    FogBugz: 'FogBugz',
    ServiceNow: 'ServiceNow',
    Slack: 'Slack',
    GitLab: 'GitLab',
    Bitbucket: 'Bitbucket',
    Unfuddle: 'Unfuddle',
    Zapier: 'Zapier',
    AzureDevOps: 'AzureDevOps',
    Redmine: 'Redmine',
    Bugzilla: 'Bugzilla',
    Kafka: 'Kafka',
    PagerDuty: 'PagerDuty',
    MicrosoftTeams: 'MicrosoftTeams',
    Clubhouse: 'Clubhouse',
    Trello: 'Trello',
    Asana: 'Asana',
    Webhook: 'Webhook',
    Kenna: 'Kenna',
    Freshservice: 'Freshservice',
    YouTrack: 'YouTrack',
    NetsparkerEnterprise: 'NetsparkerEnterprise',
    Splunk: 'Splunk',
    Mattermost: 'Mattermost',
    Hashicorp: 'Hashicorp',
    PivotalTracker: 'PivotalTracker',
    CyberArk: 'CyberArk',
    DefectDojo: 'DefectDojo',
    JazzTeam: 'JazzTeam',
    AzureKeyVault: 'AzureKeyVault',
    ServiceNowVrm: 'ServiceNowVRM'
};
/**
 * @export
 */
exports.PagerDutyIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
};
/**
 * Check if a given object implements the PagerDutyIntegrationInfoModel interface.
 */
function instanceOfPagerDutyIntegrationInfoModel(value) {
    let isInstance = true;
    isInstance = isInstance && "apiAccessKey" in value;
    isInstance = isInstance && "from" in value;
    isInstance = isInstance && "serviceId" in value;
    isInstance = isInstance && "serviceType" in value;
    isInstance = isInstance && "url" in value;
    isInstance = isInstance && "titleFormat" in value;
    return isInstance;
}
exports.instanceOfPagerDutyIntegrationInfoModel = instanceOfPagerDutyIntegrationInfoModel;
function PagerDutyIntegrationInfoModelFromJSON(json) {
    return PagerDutyIntegrationInfoModelFromJSONTyped(json, false);
}
exports.PagerDutyIntegrationInfoModelFromJSON = PagerDutyIntegrationInfoModelFromJSON;
function PagerDutyIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'apiAccessKey': json['ApiAccessKey'],
        'apiUrl': !(0, runtime_1.exists)(json, 'ApiUrl') ? undefined : json['ApiUrl'],
        'bodyDetails': !(0, runtime_1.exists)(json, 'BodyDetails') ? undefined : json['BodyDetails'],
        'from': json['From'],
        'incidentBodyType': !(0, runtime_1.exists)(json, 'IncidentBodyType') ? undefined : json['IncidentBodyType'],
        'incidentType': !(0, runtime_1.exists)(json, 'IncidentType') ? undefined : json['IncidentType'],
        'serviceId': json['ServiceId'],
        'serviceType': json['ServiceType'],
        'title': !(0, runtime_1.exists)(json, 'Title') ? undefined : json['Title'],
        'urgency': !(0, runtime_1.exists)(json, 'Urgency') ? undefined : json['Urgency'],
        'url': json['Url'],
        'type': !(0, runtime_1.exists)(json, 'Type') ? undefined : json['Type'],
        'genericErrorMessage': !(0, runtime_1.exists)(json, 'GenericErrorMessage') ? undefined : json['GenericErrorMessage'],
        'identifier': !(0, runtime_1.exists)(json, 'Identifier') ? undefined : json['Identifier'],
        'testMessageBody': !(0, runtime_1.exists)(json, 'TestMessageBody') ? undefined : json['TestMessageBody'],
        'testMessageTitle': !(0, runtime_1.exists)(json, 'TestMessageTitle') ? undefined : json['TestMessageTitle'],
        'webhookUrl': !(0, runtime_1.exists)(json, 'WebhookUrl') ? undefined : json['WebhookUrl'],
        'name': !(0, runtime_1.exists)(json, 'Name') ? undefined : json['Name'],
        'integrationVersion': !(0, runtime_1.exists)(json, 'IntegrationVersion') ? undefined : json['IntegrationVersion'],
        'accountID': !(0, runtime_1.exists)(json, 'AccountID') ? undefined : json['AccountID'],
        'customFields': !(0, runtime_1.exists)(json, 'CustomFields') ? undefined : (json['CustomFields'].map(IntegrationCustomFieldVm_1.IntegrationCustomFieldVmFromJSON)),
        'templateType': !(0, runtime_1.exists)(json, 'TemplateType') ? undefined : json['TemplateType'],
        'reopenStatus': !(0, runtime_1.exists)(json, 'ReopenStatus') ? undefined : json['ReopenStatus'],
        'resolvedStatus': !(0, runtime_1.exists)(json, 'ResolvedStatus') ? undefined : json['ResolvedStatus'],
        'titleFormat': json['TitleFormat'],
        'integrationWizardResultModel': !(0, runtime_1.exists)(json, 'IntegrationWizardResultModel') ? undefined : (0, IntegrationWizardResultModel_1.IntegrationWizardResultModelFromJSON)(json['IntegrationWizardResultModel']),
    };
}
exports.PagerDutyIntegrationInfoModelFromJSONTyped = PagerDutyIntegrationInfoModelFromJSONTyped;
function PagerDutyIntegrationInfoModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'ApiAccessKey': value.apiAccessKey,
        'BodyDetails': value.bodyDetails,
        'From': value.from,
        'ServiceId': value.serviceId,
        'ServiceType': value.serviceType,
        'Title': value.title,
        'Urgency': value.urgency,
        'Url': value.url,
        'Name': value.name,
        'IntegrationVersion': value.integrationVersion,
        'AccountID': value.accountID,
        'CustomFields': value.customFields === undefined ? undefined : (value.customFields.map(IntegrationCustomFieldVm_1.IntegrationCustomFieldVmToJSON)),
        'TemplateType': value.templateType,
        'ReopenStatus': value.reopenStatus,
        'ResolvedStatus': value.resolvedStatus,
        'TitleFormat': value.titleFormat,
        'IntegrationWizardResultModel': (0, IntegrationWizardResultModel_1.IntegrationWizardResultModelToJSON)(value.integrationWizardResultModel),
    };
}
exports.PagerDutyIntegrationInfoModelToJSON = PagerDutyIntegrationInfoModelToJSON;
//# sourceMappingURL=PagerDutyIntegrationInfoModel.js.map