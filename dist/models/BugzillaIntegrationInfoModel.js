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
exports.BugzillaIntegrationInfoModelToJSON = exports.BugzillaIntegrationInfoModelFromJSONTyped = exports.BugzillaIntegrationInfoModelFromJSON = exports.instanceOfBugzillaIntegrationInfoModel = exports.BugzillaIntegrationInfoModelTemplateTypeEnum = exports.BugzillaIntegrationInfoModelTypeEnum = void 0;
const runtime_1 = require("../runtime");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
/**
 * @export
 */
exports.BugzillaIntegrationInfoModelTypeEnum = {
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
exports.BugzillaIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
};
/**
 * Check if a given object implements the BugzillaIntegrationInfoModel interface.
 */
function instanceOfBugzillaIntegrationInfoModel(value) {
    let isInstance = true;
    isInstance = isInstance && "url" in value;
    isInstance = isInstance && "apiKey" in value;
    isInstance = isInstance && "product" in value;
    isInstance = isInstance && "component" in value;
    isInstance = isInstance && "version" in value;
    isInstance = isInstance && "platform" in value;
    isInstance = isInstance && "operationSystem" in value;
    isInstance = isInstance && "titleFormat" in value;
    return isInstance;
}
exports.instanceOfBugzillaIntegrationInfoModel = instanceOfBugzillaIntegrationInfoModel;
function BugzillaIntegrationInfoModelFromJSON(json) {
    return BugzillaIntegrationInfoModelFromJSONTyped(json, false);
}
exports.BugzillaIntegrationInfoModelFromJSON = BugzillaIntegrationInfoModelFromJSON;
function BugzillaIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'url': json['Url'],
        'apiKey': json['ApiKey'],
        'product': json['Product'],
        'component': json['Component'],
        'version': json['Version'],
        'platform': json['Platform'],
        'operationSystem': json['OperationSystem'],
        'status': !(0, runtime_1.exists)(json, 'Status') ? undefined : json['Status'],
        'priority': !(0, runtime_1.exists)(json, 'Priority') ? undefined : json['Priority'],
        'assignedTo': !(0, runtime_1.exists)(json, 'AssignedTo') ? undefined : json['AssignedTo'],
        'severity': !(0, runtime_1.exists)(json, 'Severity') ? undefined : json['Severity'],
        'milestone': !(0, runtime_1.exists)(json, 'Milestone') ? undefined : json['Milestone'],
        'dueDays': !(0, runtime_1.exists)(json, 'DueDays') ? undefined : json['DueDays'],
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
exports.BugzillaIntegrationInfoModelFromJSONTyped = BugzillaIntegrationInfoModelFromJSONTyped;
function BugzillaIntegrationInfoModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Url': value.url,
        'ApiKey': value.apiKey,
        'Product': value.product,
        'Component': value.component,
        'Version': value.version,
        'Platform': value.platform,
        'OperationSystem': value.operationSystem,
        'Status': value.status,
        'Priority': value.priority,
        'AssignedTo': value.assignedTo,
        'Severity': value.severity,
        'Milestone': value.milestone,
        'DueDays': value.dueDays,
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
exports.BugzillaIntegrationInfoModelToJSON = BugzillaIntegrationInfoModelToJSON;
//# sourceMappingURL=BugzillaIntegrationInfoModel.js.map