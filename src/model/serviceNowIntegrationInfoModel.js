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
exports.ServiceNowIntegrationInfoModel = void 0;
/**
* The ServiceNow integration info
*/
class ServiceNowIntegrationInfoModel {
    static getAttributeTypeMap() {
        return ServiceNowIntegrationInfoModel.attributeTypeMap;
    }
}
exports.ServiceNowIntegrationInfoModel = ServiceNowIntegrationInfoModel;
ServiceNowIntegrationInfoModel.discriminator = undefined;
ServiceNowIntegrationInfoModel.attributeTypeMap = [
    {
        "name": "assignedToId",
        "baseName": "AssignedToId",
        "type": "string"
    },
    {
        "name": "callerId",
        "baseName": "CallerId",
        "type": "string"
    },
    {
        "name": "serviceNowCategoryTypes",
        "baseName": "ServiceNowCategoryTypes",
        "type": "ServiceNowIntegrationInfoModel.ServiceNowCategoryTypesEnum"
    },
    {
        "name": "categoryTypes",
        "baseName": "CategoryTypes",
        "type": "string"
    },
    {
        "name": "reopenStatus",
        "baseName": "ReopenStatus",
        "type": "string"
    },
    {
        "name": "serviceNowReopenCategoryType",
        "baseName": "ServiceNowReopenCategoryType",
        "type": "ServiceNowIntegrationInfoModel.ServiceNowReopenCategoryTypeEnum"
    },
    {
        "name": "serviceNowOnHoldReasonType",
        "baseName": "ServiceNowOnHoldReasonType",
        "type": "ServiceNowIntegrationInfoModel.ServiceNowOnHoldReasonTypeEnum"
    },
    {
        "name": "closeTheFixedVulnerabilities",
        "baseName": "CloseTheFixedVulnerabilities",
        "type": "boolean"
    },
    {
        "name": "category",
        "baseName": "Category",
        "type": "string"
    },
    {
        "name": "dueDays",
        "baseName": "DueDays",
        "type": "number"
    },
    {
        "name": "severity",
        "baseName": "Severity",
        "type": "number"
    },
    {
        "name": "password",
        "baseName": "Password",
        "type": "string"
    },
    {
        "name": "resolvedStatus",
        "baseName": "ResolvedStatus",
        "type": "string"
    },
    {
        "name": "resolvedStatusServiceNow",
        "baseName": "ResolvedStatusServiceNow",
        "type": "ServiceNowIntegrationInfoModel.ResolvedStatusServiceNowEnum"
    },
    {
        "name": "type",
        "baseName": "Type",
        "type": "ServiceNowIntegrationInfoModel.TypeEnum"
    },
    {
        "name": "url",
        "baseName": "Url",
        "type": "string"
    },
    {
        "name": "webhookUrl",
        "baseName": "WebhookUrl",
        "type": "string"
    },
    {
        "name": "username",
        "baseName": "Username",
        "type": "string"
    },
    {
        "name": "templateType",
        "baseName": "TemplateType",
        "type": "ServiceNowIntegrationInfoModel.TemplateTypeEnum"
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
        "name": "integrationWizardResultModel",
        "baseName": "IntegrationWizardResultModel",
        "type": "IntegrationWizardResultModel"
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
(function (ServiceNowIntegrationInfoModel) {
    let ServiceNowCategoryTypesEnum;
    (function (ServiceNowCategoryTypesEnum) {
        ServiceNowCategoryTypesEnum[ServiceNowCategoryTypesEnum["Inquiry"] = 'Inquiry'] = "Inquiry";
        ServiceNowCategoryTypesEnum[ServiceNowCategoryTypesEnum["Software"] = 'Software'] = "Software";
        ServiceNowCategoryTypesEnum[ServiceNowCategoryTypesEnum["Hardware"] = 'Hardware'] = "Hardware";
        ServiceNowCategoryTypesEnum[ServiceNowCategoryTypesEnum["Network"] = 'Network'] = "Network";
        ServiceNowCategoryTypesEnum[ServiceNowCategoryTypesEnum["Database"] = 'Database'] = "Database";
    })(ServiceNowCategoryTypesEnum = ServiceNowIntegrationInfoModel.ServiceNowCategoryTypesEnum || (ServiceNowIntegrationInfoModel.ServiceNowCategoryTypesEnum = {}));
    let ServiceNowReopenCategoryTypeEnum;
    (function (ServiceNowReopenCategoryTypeEnum) {
        ServiceNowReopenCategoryTypeEnum[ServiceNowReopenCategoryTypeEnum["New"] = 'New'] = "New";
        ServiceNowReopenCategoryTypeEnum[ServiceNowReopenCategoryTypeEnum["InProgress"] = 'In_Progress'] = "InProgress";
        ServiceNowReopenCategoryTypeEnum[ServiceNowReopenCategoryTypeEnum["OnHold"] = 'On_Hold'] = "OnHold";
    })(ServiceNowReopenCategoryTypeEnum = ServiceNowIntegrationInfoModel.ServiceNowReopenCategoryTypeEnum || (ServiceNowIntegrationInfoModel.ServiceNowReopenCategoryTypeEnum = {}));
    let ServiceNowOnHoldReasonTypeEnum;
    (function (ServiceNowOnHoldReasonTypeEnum) {
        ServiceNowOnHoldReasonTypeEnum[ServiceNowOnHoldReasonTypeEnum["AwaitingCaller"] = 'AwaitingCaller'] = "AwaitingCaller";
        ServiceNowOnHoldReasonTypeEnum[ServiceNowOnHoldReasonTypeEnum["AwaitingChange"] = 'AwaitingChange'] = "AwaitingChange";
        ServiceNowOnHoldReasonTypeEnum[ServiceNowOnHoldReasonTypeEnum["AwaitingProblem"] = 'AwaitingProblem'] = "AwaitingProblem";
        ServiceNowOnHoldReasonTypeEnum[ServiceNowOnHoldReasonTypeEnum["AwaitingVendor"] = 'AwaitingVendor'] = "AwaitingVendor";
    })(ServiceNowOnHoldReasonTypeEnum = ServiceNowIntegrationInfoModel.ServiceNowOnHoldReasonTypeEnum || (ServiceNowIntegrationInfoModel.ServiceNowOnHoldReasonTypeEnum = {}));
    let ResolvedStatusServiceNowEnum;
    (function (ResolvedStatusServiceNowEnum) {
        ResolvedStatusServiceNowEnum[ResolvedStatusServiceNowEnum["Resolved"] = 'Resolved'] = "Resolved";
        ResolvedStatusServiceNowEnum[ResolvedStatusServiceNowEnum["Closed"] = 'Closed'] = "Closed";
    })(ResolvedStatusServiceNowEnum = ServiceNowIntegrationInfoModel.ResolvedStatusServiceNowEnum || (ServiceNowIntegrationInfoModel.ResolvedStatusServiceNowEnum = {}));
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
    })(TypeEnum = ServiceNowIntegrationInfoModel.TypeEnum || (ServiceNowIntegrationInfoModel.TypeEnum = {}));
    let TemplateTypeEnum;
    (function (TemplateTypeEnum) {
        TemplateTypeEnum[TemplateTypeEnum["Standard"] = 'Standard'] = "Standard";
        TemplateTypeEnum[TemplateTypeEnum["Detailed"] = 'Detailed'] = "Detailed";
    })(TemplateTypeEnum = ServiceNowIntegrationInfoModel.TemplateTypeEnum || (ServiceNowIntegrationInfoModel.TemplateTypeEnum = {}));
})(ServiceNowIntegrationInfoModel = exports.ServiceNowIntegrationInfoModel || (exports.ServiceNowIntegrationInfoModel = {}));
//# sourceMappingURL=serviceNowIntegrationInfoModel.js.map