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
import { IntegrationWizardResultModel } from './integrationWizardResultModel';
import { NotificationIntegrationCustomFieldModel } from './notificationIntegrationCustomFieldModel';
/**
* The GitLab integration info
*/
export declare class GitLabIntegrationInfoModel {
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
    static discriminator: string | undefined;
    static attributeTypeMap: Array<{
        name: string;
        baseName: string;
        type: string;
    }>;
    static getAttributeTypeMap(): {
        name: string;
        baseName: string;
        type: string;
    }[];
}
export declare namespace GitLabIntegrationInfoModel {
    enum TypeEnum {
        Jira,
        GitHub,
        Tfs,
        FogBugz,
        ServiceNow,
        Slack,
        GitLab,
        Bitbucket,
        Unfuddle,
        Zapier,
        AzureDevOps,
        Redmine,
        Bugzilla,
        Kafka,
        PagerDuty,
        MicrosoftTeams,
        Clubhouse,
        Trello,
        Asana,
        Webhook,
        Kenna,
        Freshservice,
        YouTrack,
        NetsparkerEnterprise,
        Splunk,
        Mattermost,
        Hashicorp,
        PivotalTracker,
        CyberArk
    }
}
