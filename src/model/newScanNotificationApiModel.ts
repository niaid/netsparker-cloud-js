/**
 * Invicti Enterprise API
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
import { NewScanNotificationRecipientApiModel } from './newScanNotificationRecipientApiModel';
import { NotificationEmailSmsFilterApi } from './notificationEmailSmsFilterApi';
import { NotificationIntegrationFilterApi } from './notificationIntegrationFilterApi';

/**
* Represents a model for carrying out a new scan notification data
*/
export class NewScanNotificationApiModel {
    'recipients': NewScanNotificationRecipientApiModel;
    /**
    * Gets or sets the website group identifier associated with this scan notification.
    */
    'websiteGroupName'?: string;
    /**
    * Gets or sets the website identifier associated with this scan notification.
    */
    'websiteRootUrl'?: string;
    'emailSmsFilter'?: NotificationEmailSmsFilterApi;
    'integrationFilter'?: NotificationIntegrationFilterApi;
    /**
    * Gets or sets a value indicating whether this Scan Notification is disabled.
    */
    'disabled': boolean;
    /**
    * Gets or sets scan task group ID.
    */
    'scanTaskGroupId'?: string;
    /**
    * Gets or sets the event name. This property determines when this rule will be executed.
    */
    'event': NewScanNotificationApiModel.EventEnum;
    /**
    * Gets or sets the name.
    */
    'name': string;
    /**
    * Gets or sets the Website Scope.  This property indicates whether this rule will be executed for a specific Website, WebsiteGroup or All Websites.
    */
    'scope': NewScanNotificationApiModel.ScopeEnum;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "recipients",
            "baseName": "Recipients",
            "type": "NewScanNotificationRecipientApiModel"
        },
        {
            "name": "websiteGroupName",
            "baseName": "WebsiteGroupName",
            "type": "string"
        },
        {
            "name": "websiteRootUrl",
            "baseName": "WebsiteRootUrl",
            "type": "string"
        },
        {
            "name": "emailSmsFilter",
            "baseName": "EmailSmsFilter",
            "type": "NotificationEmailSmsFilterApi"
        },
        {
            "name": "integrationFilter",
            "baseName": "IntegrationFilter",
            "type": "NotificationIntegrationFilterApi"
        },
        {
            "name": "disabled",
            "baseName": "Disabled",
            "type": "boolean"
        },
        {
            "name": "scanTaskGroupId",
            "baseName": "ScanTaskGroupId",
            "type": "string"
        },
        {
            "name": "event",
            "baseName": "Event",
            "type": "NewScanNotificationApiModel.EventEnum"
        },
        {
            "name": "name",
            "baseName": "Name",
            "type": "string"
        },
        {
            "name": "scope",
            "baseName": "Scope",
            "type": "NewScanNotificationApiModel.ScopeEnum"
        }    ];

    static getAttributeTypeMap() {
        return NewScanNotificationApiModel.attributeTypeMap;
    }
}

export namespace NewScanNotificationApiModel {
    export enum EventEnum {
        NewScan = <any> 'NewScan',
        ScanCompleted = <any> 'ScanCompleted',
        ScanCancelled = <any> 'ScanCancelled',
        ScanFailed = <any> 'ScanFailed',
        ScheduledScanLaunchFailed = <any> 'ScheduledScanLaunchFailed',
        OutOfDateTechnology = <any> 'OutOfDateTechnology'
    }
    export enum ScopeEnum {
        AnyWebsite = <any> 'AnyWebsite',
        WebsiteGroup = <any> 'WebsiteGroup',
        Website = <any> 'Website'
    }
}
