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
import { ScanNotificationRecipientApiModel } from './scanNotificationRecipientApiModel';

/**
* Represents a model for carrying out scan notification data
*/
export class ScanNotificationApiModel {
    /**
    * Gets or sets the scan notification identifier.
    */
    'id'?: string;
    /**
    * Gets or sets the priority. Higher value means higher priority.
    */
    'priority'?: number;
    'recipients'?: ScanNotificationRecipientApiModel;
    /**
    * Gets or sets the name of website group associated with this Scan Notification.
    */
    'websiteGroupName'?: string;
    /**
    * Gets or sets the root url of website associated with this Scan Notification.
    */
    'websiteRootUrl'?: string;
    /**
    * Gets or sets a value indicating whether this Scan Notification is certainty.
    */
    'certainty'?: number;
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
    'event': ScanNotificationApiModel.EventEnum;
    /**
    * Gets or sets a value indicating whether this Scan Notification is confirmed.
    */
    'isConfirmed'?: boolean;
    /**
    * Gets or sets the lowest severity. This property determines when this rule will be executed and is only used for Scan  Completion Notification
    */
    'severity'?: ScanNotificationApiModel.SeverityEnum;
    /**
    * Gets or sets the state of filter. This property determines when this rule will be executed and is only used for Scan  Completion Notification
    */
    'state'?: ScanNotificationApiModel.StateEnum;
    /**
    * Gets or sets the name.
    */
    'name': string;
    /**
    * Gets or sets the Website Scope.  This property indicates whether this rule will be executed for a specific Website, WebsiteGroup or All Websites.
    */
    'scope': ScanNotificationApiModel.ScopeEnum;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "id",
            "baseName": "Id",
            "type": "string"
        },
        {
            "name": "priority",
            "baseName": "Priority",
            "type": "number"
        },
        {
            "name": "recipients",
            "baseName": "Recipients",
            "type": "ScanNotificationRecipientApiModel"
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
            "name": "certainty",
            "baseName": "Certainty",
            "type": "number"
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
            "type": "ScanNotificationApiModel.EventEnum"
        },
        {
            "name": "isConfirmed",
            "baseName": "IsConfirmed",
            "type": "boolean"
        },
        {
            "name": "severity",
            "baseName": "Severity",
            "type": "ScanNotificationApiModel.SeverityEnum"
        },
        {
            "name": "state",
            "baseName": "State",
            "type": "ScanNotificationApiModel.StateEnum"
        },
        {
            "name": "name",
            "baseName": "Name",
            "type": "string"
        },
        {
            "name": "scope",
            "baseName": "Scope",
            "type": "ScanNotificationApiModel.ScopeEnum"
        }    ];

    static getAttributeTypeMap() {
        return ScanNotificationApiModel.attributeTypeMap;
    }
}

export namespace ScanNotificationApiModel {
    export enum EventEnum {
        NewScan = <any> 'NewScan',
        ScanCompleted = <any> 'ScanCompleted',
        ScanCancelled = <any> 'ScanCancelled',
        ScanFailed = <any> 'ScanFailed',
        ScheduledScanLaunchFailed = <any> 'ScheduledScanLaunchFailed',
        OutOfDateTechnology = <any> 'OutOfDateTechnology'
    }
    export enum SeverityEnum {
        BestPractice = <any> 'BestPractice',
        Information = <any> 'Information',
        Low = <any> 'Low',
        Medium = <any> 'Medium',
        High = <any> 'High',
        Critical = <any> 'Critical'
    }
    export enum StateEnum {
        NotFound = <any> 'NotFound',
        Fixed = <any> 'Fixed',
        NotFixed = <any> 'NotFixed',
        New = <any> 'New',
        Revived = <any> 'Revived'
    }
    export enum ScopeEnum {
        AnyWebsite = <any> 'AnyWebsite',
        WebsiteGroup = <any> 'WebsiteGroup',
        Website = <any> 'Website'
    }
}
