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
* The PagerDuty integration info
*/
export declare class PagerDutyIntegrationInfoModel {
    /**
    * API Access Key for authentication.
    */
    'apiAccessKey': string;
    /**
    * The PagerDuty instance URL.
    */
    'apiUrl'?: string;
    /**
    * The incident will be created on this service type.
    */
    'bodyDetails'?: string;
    /**
    * The email address of a valid user associated with the account making the request.
    */
    'from': string;
    /**
    * Type must be incident_body.
    */
    'incidentBodyType'?: string;
    /**
    * Type must be incident.
    */
    'incidentType'?: string;
    /**
    * The incident will be created on this service id.
    */
    'serviceId': string;
    /**
    * The incident will be created on this service type.
    */
    'serviceType': PagerDutyIntegrationInfoModel.ServiceTypeEnum;
    /**
    * A succinct description of the nature, symptoms, cause, or effect of the incident.
    */
    'title'?: string;
    'type'?: PagerDutyIntegrationInfoModel.TypeEnum;
    /**
    * The urgency of the incident.
    */
    'urgency'?: PagerDutyIntegrationInfoModel.UrgencyEnum;
    /**
    * The PagerDuty instance URL.
    */
    'url': string;
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
export declare namespace PagerDutyIntegrationInfoModel {
    enum ServiceTypeEnum {
        Service,
        ServiceReference
    }
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
    enum UrgencyEnum {
        High,
        Low
    }
}
