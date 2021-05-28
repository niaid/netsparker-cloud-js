"use strict";
/**
 * Netsparker Enterprise API
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
/**
* The Webhook integration info
*/
class WebhookIntegrationInfoModel {
    static getAttributeTypeMap() {
        return WebhookIntegrationInfoModel.attributeTypeMap;
    }
}
WebhookIntegrationInfoModel.discriminator = undefined;
WebhookIntegrationInfoModel.attributeTypeMap = [
    {
        "name": "httpMethodType",
        "baseName": "HttpMethodType",
        "type": "WebhookIntegrationInfoModel.HttpMethodTypeEnum"
    },
    {
        "name": "parameterType",
        "baseName": "ParameterType",
        "type": "WebhookIntegrationInfoModel.ParameterTypeEnum"
    },
    {
        "name": "url",
        "baseName": "Url",
        "type": "string"
    },
    {
        "name": "issue",
        "baseName": "Issue",
        "type": "string"
    },
    {
        "name": "customHttpHeaderModels",
        "baseName": "CustomHttpHeaderModels",
        "type": "Array<CustomHttpHeaderModel>"
    },
    {
        "name": "title",
        "baseName": "Title",
        "type": "string"
    },
    {
        "name": "body",
        "baseName": "Body",
        "type": "string"
    },
    {
        "name": "username",
        "baseName": "Username",
        "type": "string"
    },
    {
        "name": "password",
        "baseName": "Password",
        "type": "string"
    },
    {
        "name": "type",
        "baseName": "Type",
        "type": "WebhookIntegrationInfoModel.TypeEnum"
    },
    {
        "name": "accountID",
        "baseName": "AccountID",
        "type": "string"
    },
    {
        "name": "customFields",
        "baseName": "CustomFields",
        "type": "Array<NotificationIntegrationCustomFieldModel>"
    },
    {
        "name": "genericErrorMessage",
        "baseName": "GenericErrorMessage",
        "type": "string"
    },
    {
        "name": "identifier",
        "baseName": "Identifier",
        "type": "string"
    },
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    },
    {
        "name": "reopenStatus",
        "baseName": "ReopenStatus",
        "type": "string"
    },
    {
        "name": "integrationWizardResultModel",
        "baseName": "IntegrationWizardResultModel",
        "type": "IntegrationWizardResultModel"
    },
    {
        "name": "resolvedStatus",
        "baseName": "ResolvedStatus",
        "type": "string"
    },
    {
        "name": "testMessageBody",
        "baseName": "TestMessageBody",
        "type": "string"
    },
    {
        "name": "testMessageTitle",
        "baseName": "TestMessageTitle",
        "type": "string"
    },
    {
        "name": "titleFormat",
        "baseName": "TitleFormat",
        "type": "string"
    },
    {
        "name": "webhookUrl",
        "baseName": "WebhookUrl",
        "type": "string"
    }
];
exports.WebhookIntegrationInfoModel = WebhookIntegrationInfoModel;
(function (WebhookIntegrationInfoModel) {
    let HttpMethodTypeEnum;
    (function (HttpMethodTypeEnum) {
        HttpMethodTypeEnum[HttpMethodTypeEnum["Get"] = 'Get'] = "Get";
        HttpMethodTypeEnum[HttpMethodTypeEnum["Post"] = 'Post'] = "Post";
        HttpMethodTypeEnum[HttpMethodTypeEnum["Put"] = 'Put'] = "Put";
    })(HttpMethodTypeEnum = WebhookIntegrationInfoModel.HttpMethodTypeEnum || (WebhookIntegrationInfoModel.HttpMethodTypeEnum = {}));
    let ParameterTypeEnum;
    (function (ParameterTypeEnum) {
        ParameterTypeEnum[ParameterTypeEnum["Form"] = 'Form'] = "Form";
        ParameterTypeEnum[ParameterTypeEnum["Json"] = 'Json'] = "Json";
        ParameterTypeEnum[ParameterTypeEnum["Xml"] = 'Xml'] = "Xml";
        ParameterTypeEnum[ParameterTypeEnum["QueryString"] = 'QueryString'] = "QueryString";
    })(ParameterTypeEnum = WebhookIntegrationInfoModel.ParameterTypeEnum || (WebhookIntegrationInfoModel.ParameterTypeEnum = {}));
    let TypeEnum;
    (function (TypeEnum) {
        TypeEnum[TypeEnum["Jira"] = 'Jira'] = "Jira";
        TypeEnum[TypeEnum["GitHub"] = 'GitHub'] = "GitHub";
        TypeEnum[TypeEnum["Tfs"] = 'TFS'] = "Tfs";
        TypeEnum[TypeEnum["FogBugz"] = 'FogBugz'] = "FogBugz";
        TypeEnum[TypeEnum["ServiceNow"] = 'ServiceNow'] = "ServiceNow";
        TypeEnum[TypeEnum["Slack"] = 'Slack'] = "Slack";
        TypeEnum[TypeEnum["GitLab"] = 'GitLab'] = "GitLab";
        TypeEnum[TypeEnum["Bitbucket"] = 'Bitbucket'] = "Bitbucket";
        TypeEnum[TypeEnum["Unfuddle"] = 'Unfuddle'] = "Unfuddle";
        TypeEnum[TypeEnum["Zapier"] = 'Zapier'] = "Zapier";
        TypeEnum[TypeEnum["AzureDevOps"] = 'AzureDevOps'] = "AzureDevOps";
        TypeEnum[TypeEnum["Redmine"] = 'Redmine'] = "Redmine";
        TypeEnum[TypeEnum["Bugzilla"] = 'Bugzilla'] = "Bugzilla";
        TypeEnum[TypeEnum["Kafka"] = 'Kafka'] = "Kafka";
        TypeEnum[TypeEnum["PagerDuty"] = 'PagerDuty'] = "PagerDuty";
        TypeEnum[TypeEnum["MicrosoftTeams"] = 'MicrosoftTeams'] = "MicrosoftTeams";
        TypeEnum[TypeEnum["Clubhouse"] = 'Clubhouse'] = "Clubhouse";
        TypeEnum[TypeEnum["Trello"] = 'Trello'] = "Trello";
        TypeEnum[TypeEnum["Asana"] = 'Asana'] = "Asana";
        TypeEnum[TypeEnum["Webhook"] = 'Webhook'] = "Webhook";
        TypeEnum[TypeEnum["Kenna"] = 'Kenna'] = "Kenna";
        TypeEnum[TypeEnum["Freshservice"] = 'Freshservice'] = "Freshservice";
        TypeEnum[TypeEnum["YouTrack"] = 'YouTrack'] = "YouTrack";
        TypeEnum[TypeEnum["NetsparkerEnterprise"] = 'NetsparkerEnterprise'] = "NetsparkerEnterprise";
        TypeEnum[TypeEnum["Splunk"] = 'Splunk'] = "Splunk";
        TypeEnum[TypeEnum["Mattermost"] = 'Mattermost'] = "Mattermost";
        TypeEnum[TypeEnum["Hashicorp"] = 'Hashicorp'] = "Hashicorp";
        TypeEnum[TypeEnum["PivotalTracker"] = 'PivotalTracker'] = "PivotalTracker";
        TypeEnum[TypeEnum["CyberArk"] = 'CyberArk'] = "CyberArk";
    })(TypeEnum = WebhookIntegrationInfoModel.TypeEnum || (WebhookIntegrationInfoModel.TypeEnum = {}));
})(WebhookIntegrationInfoModel = exports.WebhookIntegrationInfoModel || (exports.WebhookIntegrationInfoModel = {}));
//# sourceMappingURL=webhookIntegrationInfoModel.js.map