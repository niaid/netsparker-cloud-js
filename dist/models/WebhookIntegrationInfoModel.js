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
exports.WebhookIntegrationInfoModelToJSON = exports.WebhookIntegrationInfoModelFromJSONTyped = exports.WebhookIntegrationInfoModelFromJSON = exports.instanceOfWebhookIntegrationInfoModel = exports.WebhookIntegrationInfoModelTemplateTypeEnum = exports.WebhookIntegrationInfoModelTypeEnum = exports.WebhookIntegrationInfoModelParameterTypeEnum = exports.WebhookIntegrationInfoModelHttpMethodTypeEnum = void 0;
const runtime_1 = require("../runtime");
const CustomHttpHeaderModel_1 = require("./CustomHttpHeaderModel");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
/**
* @export
* @enum {string}
*/
var WebhookIntegrationInfoModelHttpMethodTypeEnum;
(function (WebhookIntegrationInfoModelHttpMethodTypeEnum) {
    WebhookIntegrationInfoModelHttpMethodTypeEnum["Get"] = "Get";
    WebhookIntegrationInfoModelHttpMethodTypeEnum["Post"] = "Post";
    WebhookIntegrationInfoModelHttpMethodTypeEnum["Put"] = "Put";
})(WebhookIntegrationInfoModelHttpMethodTypeEnum = exports.WebhookIntegrationInfoModelHttpMethodTypeEnum || (exports.WebhookIntegrationInfoModelHttpMethodTypeEnum = {}));
/**
* @export
* @enum {string}
*/
var WebhookIntegrationInfoModelParameterTypeEnum;
(function (WebhookIntegrationInfoModelParameterTypeEnum) {
    WebhookIntegrationInfoModelParameterTypeEnum["Form"] = "Form";
    WebhookIntegrationInfoModelParameterTypeEnum["Json"] = "Json";
    WebhookIntegrationInfoModelParameterTypeEnum["Xml"] = "Xml";
    WebhookIntegrationInfoModelParameterTypeEnum["QueryString"] = "QueryString";
})(WebhookIntegrationInfoModelParameterTypeEnum = exports.WebhookIntegrationInfoModelParameterTypeEnum || (exports.WebhookIntegrationInfoModelParameterTypeEnum = {}));
/**
* @export
* @enum {string}
*/
var WebhookIntegrationInfoModelTypeEnum;
(function (WebhookIntegrationInfoModelTypeEnum) {
    WebhookIntegrationInfoModelTypeEnum["NetsparkerEnterprise"] = "NetsparkerEnterprise";
    WebhookIntegrationInfoModelTypeEnum["Webhook"] = "Webhook";
    WebhookIntegrationInfoModelTypeEnum["Zapier"] = "Zapier";
    WebhookIntegrationInfoModelTypeEnum["Slack"] = "Slack";
    WebhookIntegrationInfoModelTypeEnum["Mattermost"] = "Mattermost";
    WebhookIntegrationInfoModelTypeEnum["MicrosoftTeams"] = "MicrosoftTeams";
    WebhookIntegrationInfoModelTypeEnum["AzureDevOps"] = "AzureDevOps";
    WebhookIntegrationInfoModelTypeEnum["Bitbucket"] = "Bitbucket";
    WebhookIntegrationInfoModelTypeEnum["Bugzilla"] = "Bugzilla";
    WebhookIntegrationInfoModelTypeEnum["Clubhouse"] = "Clubhouse";
    WebhookIntegrationInfoModelTypeEnum["DefectDojo"] = "DefectDojo";
    WebhookIntegrationInfoModelTypeEnum["PivotalTracker"] = "PivotalTracker";
    WebhookIntegrationInfoModelTypeEnum["Jira"] = "Jira";
    WebhookIntegrationInfoModelTypeEnum["FogBugz"] = "FogBugz";
    WebhookIntegrationInfoModelTypeEnum["GitHub"] = "GitHub";
    WebhookIntegrationInfoModelTypeEnum["PagerDuty"] = "PagerDuty";
    WebhookIntegrationInfoModelTypeEnum["Kafka"] = "Kafka";
    WebhookIntegrationInfoModelTypeEnum["Kenna"] = "Kenna";
    WebhookIntegrationInfoModelTypeEnum["Redmine"] = "Redmine";
    WebhookIntegrationInfoModelTypeEnum["ServiceNow"] = "ServiceNow";
    WebhookIntegrationInfoModelTypeEnum["Tfs"] = "TFS";
    WebhookIntegrationInfoModelTypeEnum["Unfuddle"] = "Unfuddle";
    WebhookIntegrationInfoModelTypeEnum["YouTrack"] = "YouTrack";
    WebhookIntegrationInfoModelTypeEnum["Freshservice"] = "Freshservice";
    WebhookIntegrationInfoModelTypeEnum["Splunk"] = "Splunk";
    WebhookIntegrationInfoModelTypeEnum["JazzTeam"] = "JazzTeam";
    WebhookIntegrationInfoModelTypeEnum["ServiceNowVrm"] = "ServiceNowVRM";
    WebhookIntegrationInfoModelTypeEnum["Asana"] = "Asana";
    WebhookIntegrationInfoModelTypeEnum["Trello"] = "Trello";
    WebhookIntegrationInfoModelTypeEnum["Hashicorp"] = "Hashicorp";
    WebhookIntegrationInfoModelTypeEnum["CyberArk"] = "CyberArk";
    WebhookIntegrationInfoModelTypeEnum["AzureKeyVault"] = "AzureKeyVault";
    WebhookIntegrationInfoModelTypeEnum["GitLab"] = "GitLab";
})(WebhookIntegrationInfoModelTypeEnum = exports.WebhookIntegrationInfoModelTypeEnum || (exports.WebhookIntegrationInfoModelTypeEnum = {}));
/**
* @export
* @enum {string}
*/
var WebhookIntegrationInfoModelTemplateTypeEnum;
(function (WebhookIntegrationInfoModelTemplateTypeEnum) {
    WebhookIntegrationInfoModelTemplateTypeEnum["Standard"] = "Standard";
    WebhookIntegrationInfoModelTemplateTypeEnum["Detailed"] = "Detailed";
})(WebhookIntegrationInfoModelTemplateTypeEnum = exports.WebhookIntegrationInfoModelTemplateTypeEnum || (exports.WebhookIntegrationInfoModelTemplateTypeEnum = {}));
/**
 * Check if a given object implements the WebhookIntegrationInfoModel interface.
 */
function instanceOfWebhookIntegrationInfoModel(value) {
    let isInstance = true;
    isInstance = isInstance && "url" in value;
    isInstance = isInstance && "titleFormat" in value;
    return isInstance;
}
exports.instanceOfWebhookIntegrationInfoModel = instanceOfWebhookIntegrationInfoModel;
function WebhookIntegrationInfoModelFromJSON(json) {
    return WebhookIntegrationInfoModelFromJSONTyped(json, false);
}
exports.WebhookIntegrationInfoModelFromJSON = WebhookIntegrationInfoModelFromJSON;
function WebhookIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'httpMethodType': !(0, runtime_1.exists)(json, 'HttpMethodType') ? undefined : json['HttpMethodType'],
        'parameterType': !(0, runtime_1.exists)(json, 'ParameterType') ? undefined : json['ParameterType'],
        'url': json['Url'],
        'issue': !(0, runtime_1.exists)(json, 'Issue') ? undefined : json['Issue'],
        'customHttpHeaderModels': !(0, runtime_1.exists)(json, 'CustomHttpHeaderModels') ? undefined : (json['CustomHttpHeaderModels'].map(CustomHttpHeaderModel_1.CustomHttpHeaderModelFromJSON)),
        'title': !(0, runtime_1.exists)(json, 'Title') ? undefined : json['Title'],
        'body': !(0, runtime_1.exists)(json, 'Body') ? undefined : json['Body'],
        'username': !(0, runtime_1.exists)(json, 'Username') ? undefined : json['Username'],
        'password': !(0, runtime_1.exists)(json, 'Password') ? undefined : json['Password'],
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
exports.WebhookIntegrationInfoModelFromJSONTyped = WebhookIntegrationInfoModelFromJSONTyped;
function WebhookIntegrationInfoModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'HttpMethodType': value.httpMethodType,
        'ParameterType': value.parameterType,
        'Url': value.url,
        'Issue': value.issue,
        'CustomHttpHeaderModels': value.customHttpHeaderModels === undefined ? undefined : (value.customHttpHeaderModels.map(CustomHttpHeaderModel_1.CustomHttpHeaderModelToJSON)),
        'Title': value.title,
        'Body': value.body,
        'Username': value.username,
        'Password': value.password,
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
exports.WebhookIntegrationInfoModelToJSON = WebhookIntegrationInfoModelToJSON;
//# sourceMappingURL=WebhookIntegrationInfoModel.js.map