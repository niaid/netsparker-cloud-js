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
exports.AzureDevOpsIntegrationInfoModel = void 0;
/**
* The Azure DevOps integration info
*/
class AzureDevOpsIntegrationInfoModel {
    static getAttributeTypeMap() {
        return AzureDevOpsIntegrationInfoModel.attributeTypeMap;
    }
}
exports.AzureDevOpsIntegrationInfoModel = AzureDevOpsIntegrationInfoModel;
AzureDevOpsIntegrationInfoModel.discriminator = undefined;
AzureDevOpsIntegrationInfoModel.attributeTypeMap = [
    {
        "name": "type",
        "baseName": "Type",
        "type": "AzureDevOpsIntegrationInfoModel.TypeEnum"
    },
    {
        "name": "password",
        "baseName": "Password",
        "type": "string"
    },
    {
        "name": "username",
        "baseName": "Username",
        "type": "string"
    },
    {
        "name": "assignedTo",
        "baseName": "AssignedTo",
        "type": "string"
    },
    {
        "name": "domain",
        "baseName": "Domain",
        "type": "string"
    },
    {
        "name": "projectUri",
        "baseName": "ProjectUri",
        "type": "string"
    },
    {
        "name": "tags",
        "baseName": "Tags",
        "type": "string"
    },
    {
        "name": "workItemTypeName",
        "baseName": "WorkItemTypeName",
        "type": "string"
    },
    {
        "name": "webhookUrl",
        "baseName": "WebhookUrl",
        "type": "string"
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
    }
];
(function (AzureDevOpsIntegrationInfoModel) {
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
    })(TypeEnum = AzureDevOpsIntegrationInfoModel.TypeEnum || (AzureDevOpsIntegrationInfoModel.TypeEnum = {}));
})(AzureDevOpsIntegrationInfoModel = exports.AzureDevOpsIntegrationInfoModel || (exports.AzureDevOpsIntegrationInfoModel = {}));
//# sourceMappingURL=azureDevOpsIntegrationInfoModel.js.map