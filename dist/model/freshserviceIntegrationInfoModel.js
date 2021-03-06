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
exports.FreshserviceIntegrationInfoModel = void 0;
/**
* The Freshservice integration info
*/
class FreshserviceIntegrationInfoModel {
    static getAttributeTypeMap() {
        return FreshserviceIntegrationInfoModel.attributeTypeMap;
    }
}
exports.FreshserviceIntegrationInfoModel = FreshserviceIntegrationInfoModel;
FreshserviceIntegrationInfoModel.discriminator = undefined;
FreshserviceIntegrationInfoModel.attributeTypeMap = [
    {
        "name": "serverUrl",
        "baseName": "ServerUrl",
        "type": "string"
    },
    {
        "name": "apiKey",
        "baseName": "ApiKey",
        "type": "string"
    },
    {
        "name": "requesterId",
        "baseName": "RequesterId",
        "type": "number"
    },
    {
        "name": "groupId",
        "baseName": "GroupId",
        "type": "number"
    },
    {
        "name": "agentId",
        "baseName": "AgentId",
        "type": "number"
    },
    {
        "name": "priorityId",
        "baseName": "PriorityId",
        "type": "number"
    },
    {
        "name": "integrationWizardResultModel",
        "baseName": "IntegrationWizardResultModel",
        "type": "IntegrationWizardResultModel"
    },
    {
        "name": "requesters",
        "baseName": "Requesters",
        "type": "Array<FreshserviceUser>"
    },
    {
        "name": "groups",
        "baseName": "Groups",
        "type": "Array<FreshserviceEntity>"
    },
    {
        "name": "agents",
        "baseName": "Agents",
        "type": "Array<FreshserviceUser>"
    },
    {
        "name": "priorities",
        "baseName": "Priorities",
        "type": "Array<FreshserviceEntity>"
    },
    {
        "name": "dueDays",
        "baseName": "DueDays",
        "type": "number"
    },
    {
        "name": "type",
        "baseName": "Type",
        "type": "FreshserviceIntegrationInfoModel.TypeEnum"
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
(function (FreshserviceIntegrationInfoModel) {
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
    })(TypeEnum = FreshserviceIntegrationInfoModel.TypeEnum || (FreshserviceIntegrationInfoModel.TypeEnum = {}));
})(FreshserviceIntegrationInfoModel = exports.FreshserviceIntegrationInfoModel || (exports.FreshserviceIntegrationInfoModel = {}));
//# sourceMappingURL=freshserviceIntegrationInfoModel.js.map