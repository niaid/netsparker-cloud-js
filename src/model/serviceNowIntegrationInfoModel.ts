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

import { RequestFile } from './models';
import { IntegrationWizardResultModel } from './integrationWizardResultModel';
import { NotificationIntegrationCustomFieldModel } from './notificationIntegrationCustomFieldModel';

/**
* The ServiceNow integration info
*/
export class ServiceNowIntegrationInfoModel {
    /**
    * Gets or sets the assigned to ID.
    */
    'assignedToId'?: string;
    /**
    * Gets or sets the caller ID.
    */
    'callerId'?: string;
    /**
    * Gets or sets the category to assign cases to.
    */
    'serviceNowCategoryTypes'?: ServiceNowIntegrationInfoModel.ServiceNowCategoryTypesEnum;
    /**
    * Gets or sets the category to assign cases to.
    */
    'categoryTypes': string;
    /**
    * Gets or sets the type of the issue.
    */
    'reopenStatus'?: string;
    /**
    * Gets or sets the category types
    */
    'serviceNowReopenCategoryType'?: ServiceNowIntegrationInfoModel.ServiceNowReopenCategoryTypeEnum;
    /**
    * Gets or sets the category types
    */
    'serviceNowOnHoldReasonType'?: ServiceNowIntegrationInfoModel.ServiceNowOnHoldReasonTypeEnum;
    /**
    * if this option selected , after retesting change the status of fixed vulnerabilities to Closed..
    */
    'closeTheFixedVulnerabilities'?: boolean;
    /**
    * Gets or sets the category to assign cases to.
    */
    'category'?: string;
    /**
    * Gets or sets the due date.
    */
    'dueDays'?: number;
    /**
    * The severity of the incident.
    */
    'severity'?: number;
    /**
    * Gets or sets the ServiceNow password for the user.
    */
    'password': string;
    /**
    * Gets or sets the type of the issue. Need to be overriden for webhooks supported integrations
    */
    'resolvedStatus'?: string;
    /**
    * Gets or sets the ServiceNow resolved type of the issue.
    */
    'resolvedStatusServiceNow'?: ServiceNowIntegrationInfoModel.ResolvedStatusServiceNowEnum;
    'type'?: ServiceNowIntegrationInfoModel.TypeEnum;
    /**
    * Gets or sets the URL.
    */
    'url': string;
    /**
    * Gets FogBugz web hook URL.
    */
    'webhookUrl'?: string;
    /**
    * Gets or sets the username.
    */
    'username': string;
    /**
    * Gets or sets type of the integration issue template.
    */
    'templateType'?: ServiceNowIntegrationInfoModel.TemplateTypeEnum;
    /**
    * Gets or sets the account ID.
    */
    'accountID'?: string;
    /**
    * Gets or sets the Custom Fields.
    */
    'customFields'?: Array<NotificationIntegrationCustomFieldModel>;
    /**
    * Gets the generic error message.
    */
    'genericErrorMessage'?: string;
    /**
    * Gets or sets the request identifier.
    */
    'identifier'?: string;
    /**
    * Gets or sets the {Invicti.Cloud.Core.Models.ScanNotificationIntegration} name.
    */
    'name'?: string;
    'integrationWizardResultModel'?: IntegrationWizardResultModel;
    /**
    * Gets the test message body.
    */
    'testMessageBody'?: string;
    /**
    * Gets the test message title.
    */
    'testMessageTitle'?: string;
    /**
    * Gets or sets the title format.
    */
    'titleFormat': string;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
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
        }    ];

    static getAttributeTypeMap() {
        return ServiceNowIntegrationInfoModel.attributeTypeMap;
    }
}

export namespace ServiceNowIntegrationInfoModel {
    export enum ServiceNowCategoryTypesEnum {
        Inquiry = <any> 'Inquiry',
        Software = <any> 'Software',
        Hardware = <any> 'Hardware',
        Network = <any> 'Network',
        Database = <any> 'Database'
    }
    export enum ServiceNowReopenCategoryTypeEnum {
        New = <any> 'New',
        InProgress = <any> 'In_Progress',
        OnHold = <any> 'On_Hold'
    }
    export enum ServiceNowOnHoldReasonTypeEnum {
        AwaitingCaller = <any> 'AwaitingCaller',
        AwaitingChange = <any> 'AwaitingChange',
        AwaitingProblem = <any> 'AwaitingProblem',
        AwaitingVendor = <any> 'AwaitingVendor'
    }
    export enum ResolvedStatusServiceNowEnum {
        Resolved = <any> 'Resolved',
        Closed = <any> 'Closed'
    }
    export enum TypeEnum {
        Jira = <any> 'Jira',
        GitHub = <any> 'GitHub',
        Tfs = <any> 'TFS',
        FogBugz = <any> 'FogBugz',
        ServiceNow = <any> 'ServiceNow',
        Slack = <any> 'Slack',
        GitLab = <any> 'GitLab',
        Bitbucket = <any> 'Bitbucket',
        Unfuddle = <any> 'Unfuddle',
        Zapier = <any> 'Zapier',
        AzureDevOps = <any> 'AzureDevOps',
        Redmine = <any> 'Redmine',
        Bugzilla = <any> 'Bugzilla',
        Kafka = <any> 'Kafka',
        PagerDuty = <any> 'PagerDuty',
        MicrosoftTeams = <any> 'MicrosoftTeams',
        Clubhouse = <any> 'Clubhouse',
        Trello = <any> 'Trello',
        Asana = <any> 'Asana',
        Webhook = <any> 'Webhook',
        Kenna = <any> 'Kenna',
        Freshservice = <any> 'Freshservice',
        YouTrack = <any> 'YouTrack',
        NetsparkerEnterprise = <any> 'NetsparkerEnterprise',
        Splunk = <any> 'Splunk',
        Mattermost = <any> 'Mattermost',
        Hashicorp = <any> 'Hashicorp',
        PivotalTracker = <any> 'PivotalTracker',
        CyberArk = <any> 'CyberArk'
    }
    export enum TemplateTypeEnum {
        Standard = <any> 'Standard',
        Detailed = <any> 'Detailed'
    }
}