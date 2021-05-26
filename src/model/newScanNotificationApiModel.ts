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
import { NewScanNotificationRecipientApiModel } from './newScanNotificationRecipientApiModel';

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
    'event': NewScanNotificationApiModel.EventEnum;
    /**
    * Gets or sets a value indicating whether this Scan Notification is confirmed.
    */
    'isConfirmed'?: boolean;
    /**
    * Gets or sets the lowest severity. This property determines when this rule will be executed and is only used for Scan  Completion Notification
    */
    'severity'?: NewScanNotificationApiModel.SeverityEnum;
    /**
    * Gets or sets the state of filter. This property determines when this rule will be executed and is only used for Scan  Completion Notification
    */
    'state'?: NewScanNotificationApiModel.StateEnum;
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
            "type": "NewScanNotificationApiModel.EventEnum"
        },
        {
            "name": "isConfirmed",
            "baseName": "IsConfirmed",
            "type": "boolean"
        },
        {
            "name": "severity",
            "baseName": "Severity",
            "type": "NewScanNotificationApiModel.SeverityEnum"
        },
        {
            "name": "state",
            "baseName": "State",
            "type": "NewScanNotificationApiModel.StateEnum"
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
