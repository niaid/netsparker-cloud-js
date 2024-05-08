/* tslint:disable */
/* eslint-disable */
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

import { mapValues } from '../runtime';
import type { NotificationEmailSmsFilterApi } from './NotificationEmailSmsFilterApi';
import {
    NotificationEmailSmsFilterApiFromJSON,
    NotificationEmailSmsFilterApiFromJSONTyped,
    NotificationEmailSmsFilterApiToJSON,
} from './NotificationEmailSmsFilterApi';
import type { NewScanNotificationRecipientApiModel } from './NewScanNotificationRecipientApiModel';
import {
    NewScanNotificationRecipientApiModelFromJSON,
    NewScanNotificationRecipientApiModelFromJSONTyped,
    NewScanNotificationRecipientApiModelToJSON,
} from './NewScanNotificationRecipientApiModel';
import type { NotificationIntegrationFilterApi } from './NotificationIntegrationFilterApi';
import {
    NotificationIntegrationFilterApiFromJSON,
    NotificationIntegrationFilterApiFromJSONTyped,
    NotificationIntegrationFilterApiToJSON,
} from './NotificationIntegrationFilterApi';

/**
 * Represents a model for carrying out a new scan notification data
 * @export
 * @interface NewScanNotificationApiModel
 */
export interface NewScanNotificationApiModel {
    /**
     * 
     * @type {NewScanNotificationRecipientApiModel}
     * @memberof NewScanNotificationApiModel
     */
    recipients: NewScanNotificationRecipientApiModel;
    /**
     * Gets or sets the website group identifier associated with this scan notification.
     * @type {string}
     * @memberof NewScanNotificationApiModel
     */
    websiteGroupName?: string;
    /**
     * Gets or sets the website identifier associated with this scan notification.
     * @type {string}
     * @memberof NewScanNotificationApiModel
     */
    websiteRootUrl?: string;
    /**
     * 
     * @type {NotificationEmailSmsFilterApi}
     * @memberof NewScanNotificationApiModel
     */
    emailSmsFilter?: NotificationEmailSmsFilterApi;
    /**
     * 
     * @type {NotificationIntegrationFilterApi}
     * @memberof NewScanNotificationApiModel
     */
    integrationFilter?: NotificationIntegrationFilterApi;
    /**
     * Gets or sets a value indicating whether this Scan Notification is disabled.
     * @type {boolean}
     * @memberof NewScanNotificationApiModel
     */
    disabled: boolean;
    /**
     * Gets or sets scan task group ID.
     * @type {string}
     * @memberof NewScanNotificationApiModel
     */
    scanTaskGroupId?: string;
    /**
     * Gets or sets the event name. This property determines when this rule will be executed.
     * @type {string}
     * @memberof NewScanNotificationApiModel
     */
    event: NewScanNotificationApiModelEventEnum;
    /**
     * Gets or sets the name.
     * @type {string}
     * @memberof NewScanNotificationApiModel
     */
    name: string;
    /**
     * Gets or sets the Website Scope.
     * This property indicates whether this rule will be executed for a specific Website, WebsiteGroup or All Websites.
     * @type {string}
     * @memberof NewScanNotificationApiModel
     */
    scope: NewScanNotificationApiModelScopeEnum;
}


/**
 * @export
 */
export const NewScanNotificationApiModelEventEnum = {
    NewScan: 'NewScan',
    ScanCompleted: 'ScanCompleted',
    ScanCancelled: 'ScanCancelled',
    ScanFailed: 'ScanFailed',
    ScheduledScanLaunchFailed: 'ScheduledScanLaunchFailed',
    OutOfDateTechnology: 'OutOfDateTechnology'
} as const;
export type NewScanNotificationApiModelEventEnum = typeof NewScanNotificationApiModelEventEnum[keyof typeof NewScanNotificationApiModelEventEnum];

/**
 * @export
 */
export const NewScanNotificationApiModelScopeEnum = {
    AnyWebsite: 'AnyWebsite',
    WebsiteGroup: 'WebsiteGroup',
    Website: 'Website'
} as const;
export type NewScanNotificationApiModelScopeEnum = typeof NewScanNotificationApiModelScopeEnum[keyof typeof NewScanNotificationApiModelScopeEnum];


/**
 * Check if a given object implements the NewScanNotificationApiModel interface.
 */
export function instanceOfNewScanNotificationApiModel(value: object): boolean {
    if (!('recipients' in value)) return false;
    if (!('disabled' in value)) return false;
    if (!('event' in value)) return false;
    if (!('name' in value)) return false;
    if (!('scope' in value)) return false;
    return true;
}

export function NewScanNotificationApiModelFromJSON(json: any): NewScanNotificationApiModel {
    return NewScanNotificationApiModelFromJSONTyped(json, false);
}

export function NewScanNotificationApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): NewScanNotificationApiModel {
    if (json == null) {
        return json;
    }
    return {
        
        'recipients': NewScanNotificationRecipientApiModelFromJSON(json['Recipients']),
        'websiteGroupName': json['WebsiteGroupName'] == null ? undefined : json['WebsiteGroupName'],
        'websiteRootUrl': json['WebsiteRootUrl'] == null ? undefined : json['WebsiteRootUrl'],
        'emailSmsFilter': json['EmailSmsFilter'] == null ? undefined : NotificationEmailSmsFilterApiFromJSON(json['EmailSmsFilter']),
        'integrationFilter': json['IntegrationFilter'] == null ? undefined : NotificationIntegrationFilterApiFromJSON(json['IntegrationFilter']),
        'disabled': json['Disabled'],
        'scanTaskGroupId': json['ScanTaskGroupId'] == null ? undefined : json['ScanTaskGroupId'],
        'event': json['Event'],
        'name': json['Name'],
        'scope': json['Scope'],
    };
}

export function NewScanNotificationApiModelToJSON(value?: NewScanNotificationApiModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Recipients': NewScanNotificationRecipientApiModelToJSON(value['recipients']),
        'WebsiteGroupName': value['websiteGroupName'],
        'WebsiteRootUrl': value['websiteRootUrl'],
        'EmailSmsFilter': NotificationEmailSmsFilterApiToJSON(value['emailSmsFilter']),
        'IntegrationFilter': NotificationIntegrationFilterApiToJSON(value['integrationFilter']),
        'Disabled': value['disabled'],
        'ScanTaskGroupId': value['scanTaskGroupId'],
        'Event': value['event'],
        'Name': value['name'],
        'Scope': value['scope'],
    };
}

