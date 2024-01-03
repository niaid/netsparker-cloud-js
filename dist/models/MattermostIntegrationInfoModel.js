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
exports.MattermostIntegrationInfoModelToJSON = exports.MattermostIntegrationInfoModelFromJSONTyped = exports.MattermostIntegrationInfoModelFromJSON = exports.instanceOfMattermostIntegrationInfoModel = exports.MattermostIntegrationInfoModelTemplateTypeEnum = exports.MattermostIntegrationInfoModelTypeEnum = void 0;
const runtime_1 = require("../runtime");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
/**
* @export
* @enum {string}
*/
var MattermostIntegrationInfoModelTypeEnum;
(function (MattermostIntegrationInfoModelTypeEnum) {
    MattermostIntegrationInfoModelTypeEnum["NetsparkerEnterprise"] = "NetsparkerEnterprise";
    MattermostIntegrationInfoModelTypeEnum["Webhook"] = "Webhook";
    MattermostIntegrationInfoModelTypeEnum["Zapier"] = "Zapier";
    MattermostIntegrationInfoModelTypeEnum["Slack"] = "Slack";
    MattermostIntegrationInfoModelTypeEnum["Mattermost"] = "Mattermost";
    MattermostIntegrationInfoModelTypeEnum["MicrosoftTeams"] = "MicrosoftTeams";
    MattermostIntegrationInfoModelTypeEnum["AzureDevOps"] = "AzureDevOps";
    MattermostIntegrationInfoModelTypeEnum["Bitbucket"] = "Bitbucket";
    MattermostIntegrationInfoModelTypeEnum["Bugzilla"] = "Bugzilla";
    MattermostIntegrationInfoModelTypeEnum["Clubhouse"] = "Clubhouse";
    MattermostIntegrationInfoModelTypeEnum["DefectDojo"] = "DefectDojo";
    MattermostIntegrationInfoModelTypeEnum["PivotalTracker"] = "PivotalTracker";
    MattermostIntegrationInfoModelTypeEnum["Jira"] = "Jira";
    MattermostIntegrationInfoModelTypeEnum["FogBugz"] = "FogBugz";
    MattermostIntegrationInfoModelTypeEnum["GitHub"] = "GitHub";
    MattermostIntegrationInfoModelTypeEnum["PagerDuty"] = "PagerDuty";
    MattermostIntegrationInfoModelTypeEnum["Kafka"] = "Kafka";
    MattermostIntegrationInfoModelTypeEnum["Kenna"] = "Kenna";
    MattermostIntegrationInfoModelTypeEnum["Redmine"] = "Redmine";
    MattermostIntegrationInfoModelTypeEnum["ServiceNow"] = "ServiceNow";
    MattermostIntegrationInfoModelTypeEnum["Tfs"] = "TFS";
    MattermostIntegrationInfoModelTypeEnum["Unfuddle"] = "Unfuddle";
    MattermostIntegrationInfoModelTypeEnum["YouTrack"] = "YouTrack";
    MattermostIntegrationInfoModelTypeEnum["Freshservice"] = "Freshservice";
    MattermostIntegrationInfoModelTypeEnum["Splunk"] = "Splunk";
    MattermostIntegrationInfoModelTypeEnum["JazzTeam"] = "JazzTeam";
    MattermostIntegrationInfoModelTypeEnum["ServiceNowVrm"] = "ServiceNowVRM";
    MattermostIntegrationInfoModelTypeEnum["Asana"] = "Asana";
    MattermostIntegrationInfoModelTypeEnum["Trello"] = "Trello";
    MattermostIntegrationInfoModelTypeEnum["Hashicorp"] = "Hashicorp";
    MattermostIntegrationInfoModelTypeEnum["CyberArk"] = "CyberArk";
    MattermostIntegrationInfoModelTypeEnum["AzureKeyVault"] = "AzureKeyVault";
    MattermostIntegrationInfoModelTypeEnum["GitLab"] = "GitLab";
})(MattermostIntegrationInfoModelTypeEnum = exports.MattermostIntegrationInfoModelTypeEnum || (exports.MattermostIntegrationInfoModelTypeEnum = {}));
/**
* @export
* @enum {string}
*/
var MattermostIntegrationInfoModelTemplateTypeEnum;
(function (MattermostIntegrationInfoModelTemplateTypeEnum) {
    MattermostIntegrationInfoModelTemplateTypeEnum["Standard"] = "Standard";
    MattermostIntegrationInfoModelTemplateTypeEnum["Detailed"] = "Detailed";
})(MattermostIntegrationInfoModelTemplateTypeEnum = exports.MattermostIntegrationInfoModelTemplateTypeEnum || (exports.MattermostIntegrationInfoModelTemplateTypeEnum = {}));
/**
 * Check if a given object implements the MattermostIntegrationInfoModel interface.
 */
function instanceOfMattermostIntegrationInfoModel(value) {
    let isInstance = true;
    isInstance = isInstance && "incomingWebhookUrl" in value;
    isInstance = isInstance && "titleFormat" in value;
    return isInstance;
}
exports.instanceOfMattermostIntegrationInfoModel = instanceOfMattermostIntegrationInfoModel;
function MattermostIntegrationInfoModelFromJSON(json) {
    return MattermostIntegrationInfoModelFromJSONTyped(json, false);
}
exports.MattermostIntegrationInfoModelFromJSON = MattermostIntegrationInfoModelFromJSON;
function MattermostIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'incomingWebhookUrl': json['IncomingWebhookUrl'],
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
exports.MattermostIntegrationInfoModelFromJSONTyped = MattermostIntegrationInfoModelFromJSONTyped;
function MattermostIntegrationInfoModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'IncomingWebhookUrl': value.incomingWebhookUrl,
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
exports.MattermostIntegrationInfoModelToJSON = MattermostIntegrationInfoModelToJSON;
//# sourceMappingURL=MattermostIntegrationInfoModel.js.map