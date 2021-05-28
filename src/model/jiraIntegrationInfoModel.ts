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
import { IntegrationUserMappingItemModel } from './integrationUserMappingItemModel';
import { IntegrationWizardResultModel } from './integrationWizardResultModel';
import { NotificationIntegrationCustomFieldModel } from './notificationIntegrationCustomFieldModel';

/**
* The Jira integration info
*/
export class JiraIntegrationInfoModel {
    'assignedTo'?: string;
    'autoAssignToPerson'?: boolean;
    'dueDays'?: number;
    'isCloud'?: boolean;
    'issueType': string;
    'labels'?: string;
    'components'?: string;
    'mappedJiraUsers'?: Array<IntegrationUserMappingItemModel>;
    'password': string;
    /**
    * Gets or sets the priority.
    */
    'priority'?: string;
    /**
    * The issue security level.
    */
    'securityLevel'?: string;
    'projectKey': string;
    /**
    * Gets or sets the type of the issue.
    */
    'reopenStatus'?: string;
    /**
    * Gets or sets the jira reopen type of the issue.
    */
    'reopenStatusJira'?: JiraIntegrationInfoModel.ReopenStatusJiraEnum;
    'reporter'?: string;
    'type'?: JiraIntegrationInfoModel.TypeEnum;
    'url': string;
    'usernameOrEmail': string;
    'webhookUrl'?: string;
    /**
    * Gets or sets type of the jira template.
    */
    'templateType'?: JiraIntegrationInfoModel.TemplateTypeEnum;
    /**
    * Gets or sets type of the jira epic name
    */
    'epicName'?: string;
    /**
    * Gets or sets type of the jira epic name custom field name
    */
    'epicNameCustomFieldName'?: string;
    /**
    * Gets or sets type of the jira epic key
    */
    'epicKey'?: string;
    /**
    * Gets or sets type of the jira epic key custom field name
    */
    'epicKeyCustomFieldName'?: string;
    /**
    * Gets or sets type of the jira epic type
    */
    'epicSelectionType'?: JiraIntegrationInfoModel.EpicSelectionTypeEnum;
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
    * Gets or sets the type of the issue.
    */
    'resolvedStatus'?: string;
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
            "name": "assignedTo",
            "baseName": "AssignedTo",
            "type": "string"
        },
        {
            "name": "autoAssignToPerson",
            "baseName": "AutoAssignToPerson",
            "type": "boolean"
        },
        {
            "name": "dueDays",
            "baseName": "DueDays",
            "type": "number"
        },
        {
            "name": "isCloud",
            "baseName": "IsCloud",
            "type": "boolean"
        },
        {
            "name": "issueType",
            "baseName": "IssueType",
            "type": "string"
        },
        {
            "name": "labels",
            "baseName": "Labels",
            "type": "string"
        },
        {
            "name": "components",
            "baseName": "Components",
            "type": "string"
        },
        {
            "name": "mappedJiraUsers",
            "baseName": "MappedJiraUsers",
            "type": "Array<IntegrationUserMappingItemModel>"
        },
        {
            "name": "password",
            "baseName": "Password",
            "type": "string"
        },
        {
            "name": "priority",
            "baseName": "Priority",
            "type": "string"
        },
        {
            "name": "securityLevel",
            "baseName": "SecurityLevel",
            "type": "string"
        },
        {
            "name": "projectKey",
            "baseName": "ProjectKey",
            "type": "string"
        },
        {
            "name": "reopenStatus",
            "baseName": "ReopenStatus",
            "type": "string"
        },
        {
            "name": "reopenStatusJira",
            "baseName": "ReopenStatusJira",
            "type": "JiraIntegrationInfoModel.ReopenStatusJiraEnum"
        },
        {
            "name": "reporter",
            "baseName": "Reporter",
            "type": "string"
        },
        {
            "name": "type",
            "baseName": "Type",
            "type": "JiraIntegrationInfoModel.TypeEnum"
        },
        {
            "name": "url",
            "baseName": "Url",
            "type": "string"
        },
        {
            "name": "usernameOrEmail",
            "baseName": "UsernameOrEmail",
            "type": "string"
        },
        {
            "name": "webhookUrl",
            "baseName": "WebhookUrl",
            "type": "string"
        },
        {
            "name": "templateType",
            "baseName": "TemplateType",
            "type": "JiraIntegrationInfoModel.TemplateTypeEnum"
        },
        {
            "name": "epicName",
            "baseName": "EpicName",
            "type": "string"
        },
        {
            "name": "epicNameCustomFieldName",
            "baseName": "EpicNameCustomFieldName",
            "type": "string"
        },
        {
            "name": "epicKey",
            "baseName": "EpicKey",
            "type": "string"
        },
        {
            "name": "epicKeyCustomFieldName",
            "baseName": "EpicKeyCustomFieldName",
            "type": "string"
        },
        {
            "name": "epicSelectionType",
            "baseName": "EpicSelectionType",
            "type": "JiraIntegrationInfoModel.EpicSelectionTypeEnum"
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
        }    ];

    static getAttributeTypeMap() {
        return JiraIntegrationInfoModel.attributeTypeMap;
    }
}

export namespace JiraIntegrationInfoModel {
    export enum ReopenStatusJiraEnum {
        ToDo = <any> 'ToDo',
        InProgress = <any> 'InProgress'
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
    export enum EpicSelectionTypeEnum {
        None = <any> 'None',
        EpicName = <any> 'EpicName',
        EpicKey = <any> 'EpicKey'
    }
}