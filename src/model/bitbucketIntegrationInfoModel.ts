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
* The Bitbucket integration info
*/
export class BitbucketIntegrationInfoModel {
    /**
    * Gets or sets the kind.
    */
    'kind': string;
    /**
    * Gets or sets the password.
    */
    'password': string;
    /**
    * Gets or sets the priority.
    */
    'priority': string;
    /**
    * Gets or sets the repository.
    */
    'repository': string;
    'type'?: BitbucketIntegrationInfoModel.TypeEnum;
    /**
    * Gets or sets the username.
    */
    'usernameOrEmail': string;
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
            "name": "kind",
            "baseName": "Kind",
            "type": "string"
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
            "name": "repository",
            "baseName": "Repository",
            "type": "string"
        },
        {
            "name": "type",
            "baseName": "Type",
            "type": "BitbucketIntegrationInfoModel.TypeEnum"
        },
        {
            "name": "usernameOrEmail",
            "baseName": "UsernameOrEmail",
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
        },
        {
            "name": "webhookUrl",
            "baseName": "WebhookUrl",
            "type": "string"
        }    ];

    static getAttributeTypeMap() {
        return BitbucketIntegrationInfoModel.attributeTypeMap;
    }
}

export namespace BitbucketIntegrationInfoModel {
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
