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
* The GitLab integration info
*/
export class GitLabIntegrationInfoModel {
    /**
    * Gets or sets the access token.
    */
    'accessToken': string;
    /**
    * Gets or sets the assignee id.
    */
    'assigneeId'?: number;
    /**
    * Gets or sets the due days.
    */
    'dueDays'?: number;
    /**
    * Gets or sets the labels.
    */
    'labels'?: string;
    /**
    * Gets or sets the milestone id.
    */
    'milestoneId'?: number;
    /**
    * Gets or sets the on-premise base url.
    */
    'onPremiseBaseURL'?: string;
    /**
    * Gets or sets the project id.
    */
    'projectId': number;
    'type'?: GitLabIntegrationInfoModel.TypeEnum;
    /**
    * Gets or sets the weight.
    */
    'weight'?: number;
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
    /**
    * Gets or sets the type of the issue.
    */
    'reopenStatus'?: string;
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
    /**
    * Gets the webhook URL.
    */
    'webhookUrl'?: string;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "accessToken",
            "baseName": "AccessToken",
            "type": "string"
        },
        {
            "name": "assigneeId",
            "baseName": "AssigneeId",
            "type": "number"
        },
        {
            "name": "dueDays",
            "baseName": "DueDays",
            "type": "number"
        },
        {
            "name": "labels",
            "baseName": "Labels",
            "type": "string"
        },
        {
            "name": "milestoneId",
            "baseName": "MilestoneId",
            "type": "number"
        },
        {
            "name": "onPremiseBaseURL",
            "baseName": "OnPremiseBaseURL",
            "type": "string"
        },
        {
            "name": "projectId",
            "baseName": "ProjectId",
            "type": "number"
        },
        {
            "name": "type",
            "baseName": "Type",
            "type": "GitLabIntegrationInfoModel.TypeEnum"
        },
        {
            "name": "weight",
            "baseName": "Weight",
            "type": "number"
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
        }    ];

    static getAttributeTypeMap() {
        return GitLabIntegrationInfoModel.attributeTypeMap;
    }
}

export namespace GitLabIntegrationInfoModel {
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
}
