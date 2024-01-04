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
exports.HashicorpVaultIntegrationInfoModelToJSON = exports.HashicorpVaultIntegrationInfoModelFromJSONTyped = exports.HashicorpVaultIntegrationInfoModelFromJSON = exports.instanceOfHashicorpVaultIntegrationInfoModel = exports.HashicorpVaultIntegrationInfoModelTemplateTypeEnum = exports.HashicorpVaultIntegrationInfoModelTypeEnum = exports.HashicorpVaultIntegrationInfoModelAuthTypeEnum = exports.HashicorpVaultIntegrationInfoModelAgentModeEnum = void 0;
const runtime_1 = require("../runtime");
const CertificateInfoModel_1 = require("./CertificateInfoModel");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
/**
 * @export
 */
exports.HashicorpVaultIntegrationInfoModelAgentModeEnum = {
    Cloud: 'Cloud',
    Internal: 'Internal'
};
/**
 * @export
 */
exports.HashicorpVaultIntegrationInfoModelAuthTypeEnum = {
    Token: 'Token',
    TlsCert: 'TLSCert'
};
/**
 * @export
 */
exports.HashicorpVaultIntegrationInfoModelTypeEnum = {
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
exports.HashicorpVaultIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
};
/**
 * Check if a given object implements the HashicorpVaultIntegrationInfoModel interface.
 */
function instanceOfHashicorpVaultIntegrationInfoModel(value) {
    let isInstance = true;
    isInstance = isInstance && "token" in value;
    isInstance = isInstance && "url" in value;
    isInstance = isInstance && "titleFormat" in value;
    return isInstance;
}
exports.instanceOfHashicorpVaultIntegrationInfoModel = instanceOfHashicorpVaultIntegrationInfoModel;
function HashicorpVaultIntegrationInfoModelFromJSON(json) {
    return HashicorpVaultIntegrationInfoModelFromJSONTyped(json, false);
}
exports.HashicorpVaultIntegrationInfoModelFromJSON = HashicorpVaultIntegrationInfoModelFromJSON;
function HashicorpVaultIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'token': json['Token'],
        'agentMode': !(0, runtime_1.exists)(json, 'AgentMode') ? undefined : json['AgentMode'],
        'authType': !(0, runtime_1.exists)(json, 'AuthType') ? undefined : json['AuthType'],
        'url': json['Url'],
        'certificateFileEncrypted': !(0, runtime_1.exists)(json, 'CertificateFileEncrypted') ? undefined : json['CertificateFileEncrypted'],
        'certificateFilePassword': !(0, runtime_1.exists)(json, 'CertificateFilePassword') ? undefined : json['CertificateFilePassword'],
        'path': !(0, runtime_1.exists)(json, 'Path') ? undefined : json['Path'],
        'namespace': !(0, runtime_1.exists)(json, 'Namespace') ? undefined : json['Namespace'],
        'certificateInfoModel': !(0, runtime_1.exists)(json, 'CertificateInfoModel') ? undefined : (0, CertificateInfoModel_1.CertificateInfoModelFromJSON)(json['CertificateInfoModel']),
        'hasCertificate': !(0, runtime_1.exists)(json, 'HasCertificate') ? undefined : json['HasCertificate'],
        'updatedAt': !(0, runtime_1.exists)(json, 'UpdatedAt') ? undefined : (new Date(json['UpdatedAt'])),
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
exports.HashicorpVaultIntegrationInfoModelFromJSONTyped = HashicorpVaultIntegrationInfoModelFromJSONTyped;
function HashicorpVaultIntegrationInfoModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Token': value.token,
        'AgentMode': value.agentMode,
        'AuthType': value.authType,
        'Url': value.url,
        'CertificateFileEncrypted': value.certificateFileEncrypted,
        'CertificateFilePassword': value.certificateFilePassword,
        'Path': value.path,
        'Namespace': value.namespace,
        'CertificateInfoModel': (0, CertificateInfoModel_1.CertificateInfoModelToJSON)(value.certificateInfoModel),
        'HasCertificate': value.hasCertificate,
        'UpdatedAt': value.updatedAt === undefined ? undefined : (value.updatedAt.toISOString()),
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
exports.HashicorpVaultIntegrationInfoModelToJSON = HashicorpVaultIntegrationInfoModelToJSON;
//# sourceMappingURL=HashicorpVaultIntegrationInfoModel.js.map