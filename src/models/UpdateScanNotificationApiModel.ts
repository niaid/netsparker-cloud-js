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

import { exists, mapValues } from '../runtime';
import type { NewScanNotificationRecipientApiModel } from './NewScanNotificationRecipientApiModel';
import {
    NewScanNotificationRecipientApiModelFromJSON,
    NewScanNotificationRecipientApiModelFromJSONTyped,
    NewScanNotificationRecipientApiModelToJSON,
} from './NewScanNotificationRecipientApiModel';
import type { NotificationEmailSmsFilterApi } from './NotificationEmailSmsFilterApi';
import {
    NotificationEmailSmsFilterApiFromJSON,
    NotificationEmailSmsFilterApiFromJSONTyped,
    NotificationEmailSmsFilterApiToJSON,
} from './NotificationEmailSmsFilterApi';
import type { NotificationIntegrationFilterApi } from './NotificationIntegrationFilterApi';
import {
    NotificationIntegrationFilterApiFromJSON,
    NotificationIntegrationFilterApiFromJSONTyped,
    NotificationIntegrationFilterApiToJSON,
} from './NotificationIntegrationFilterApi';

/**
 * Represents a model for carrying out an update scan notification data
 * @export
 * @interface UpdateScanNotificationApiModel
 */
export interface UpdateScanNotificationApiModel {
    /**
     * Gets or sets the scan notification identifier.
     * @type {string}
     * @memberof UpdateScanNotificationApiModel
     */
    id: string;
    /**
     * 
     * @type {NewScanNotificationRecipientApiModel}
     * @memberof UpdateScanNotificationApiModel
     */
    recipients: NewScanNotificationRecipientApiModel;
    /**
     * Gets or sets the website group identifier associated with this scan notification.
     * @type {string}
     * @memberof UpdateScanNotificationApiModel
     */
    websiteGroupName?: string;
    /**
     * Gets or sets the website identifier associated with this scan notification.
     * @type {string}
     * @memberof UpdateScanNotificationApiModel
     */
    websiteRootUrl?: string;
    /**
     * 
     * @type {NotificationEmailSmsFilterApi}
     * @memberof UpdateScanNotificationApiModel
     */
    emailSmsFilter?: NotificationEmailSmsFilterApi;
    /**
     * 
     * @type {NotificationIntegrationFilterApi}
     * @memberof UpdateScanNotificationApiModel
     */
    integrationFilter?: NotificationIntegrationFilterApi;
    /**
     * Gets or sets a value indicating whether this Scan Notification is disabled.
     * @type {boolean}
     * @memberof UpdateScanNotificationApiModel
     */
    disabled: boolean;
    /**
     * Gets or sets scan task group ID.
     * @type {string}
     * @memberof UpdateScanNotificationApiModel
     */
    scanTaskGroupId?: string;
    /**
     * Gets or sets the event name. This property determines when this rule will be executed.
     * @type {string}
     * @memberof UpdateScanNotificationApiModel
     */
    event: UpdateScanNotificationApiModelEventEnum;
    /**
     * Gets or sets the name.
     * @type {string}
     * @memberof UpdateScanNotificationApiModel
     */
    name: string;
    /**
     * Gets or sets the Website Scope.
     * This property indicates whether this rule will be executed for a specific Website, WebsiteGroup or All Websites.
     * @type {string}
     * @memberof UpdateScanNotificationApiModel
     */
    scope: UpdateScanNotificationApiModelScopeEnum;
}


/**
 * @export
 */
export const UpdateScanNotificationApiModelEventEnum = {
    NewScan: 'NewScan',
    ScanCompleted: 'ScanCompleted',
    ScanCancelled: 'ScanCancelled',
    ScanFailed: 'ScanFailed',
    ScheduledScanLaunchFailed: 'ScheduledScanLaunchFailed',
    OutOfDateTechnology: 'OutOfDateTechnology'
} as const;
export type UpdateScanNotificationApiModelEventEnum = typeof UpdateScanNotificationApiModelEventEnum[keyof typeof UpdateScanNotificationApiModelEventEnum];

/**
 * @export
 */
export const UpdateScanNotificationApiModelScopeEnum = {
    AnyWebsite: 'AnyWebsite',
    WebsiteGroup: 'WebsiteGroup',
    Website: 'Website'
} as const;
export type UpdateScanNotificationApiModelScopeEnum = typeof UpdateScanNotificationApiModelScopeEnum[keyof typeof UpdateScanNotificationApiModelScopeEnum];


/**
 * Check if a given object implements the UpdateScanNotificationApiModel interface.
 */
export function instanceOfUpdateScanNotificationApiModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "id" in value;
    isInstance = isInstance && "recipients" in value;
    isInstance = isInstance && "disabled" in value;
    isInstance = isInstance && "event" in value;
    isInstance = isInstance && "name" in value;
    isInstance = isInstance && "scope" in value;

    return isInstance;
}

export function UpdateScanNotificationApiModelFromJSON(json: any): UpdateScanNotificationApiModel {
    return UpdateScanNotificationApiModelFromJSONTyped(json, false);
}

export function UpdateScanNotificationApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): UpdateScanNotificationApiModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'id': json['Id'],
        'recipients': NewScanNotificationRecipientApiModelFromJSON(json['Recipients']),
        'websiteGroupName': !exists(json, 'WebsiteGroupName') ? undefined : json['WebsiteGroupName'],
        'websiteRootUrl': !exists(json, 'WebsiteRootUrl') ? undefined : json['WebsiteRootUrl'],
        'emailSmsFilter': !exists(json, 'EmailSmsFilter') ? undefined : NotificationEmailSmsFilterApiFromJSON(json['EmailSmsFilter']),
        'integrationFilter': !exists(json, 'IntegrationFilter') ? undefined : NotificationIntegrationFilterApiFromJSON(json['IntegrationFilter']),
        'disabled': json['Disabled'],
        'scanTaskGroupId': !exists(json, 'ScanTaskGroupId') ? undefined : json['ScanTaskGroupId'],
        'event': json['Event'],
        'name': json['Name'],
        'scope': json['Scope'],
    };
}

export function UpdateScanNotificationApiModelToJSON(value?: UpdateScanNotificationApiModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Id': value.id,
        'Recipients': NewScanNotificationRecipientApiModelToJSON(value.recipients),
        'WebsiteGroupName': value.websiteGroupName,
        'WebsiteRootUrl': value.websiteRootUrl,
        'EmailSmsFilter': NotificationEmailSmsFilterApiToJSON(value.emailSmsFilter),
        'IntegrationFilter': NotificationIntegrationFilterApiToJSON(value.integrationFilter),
        'Disabled': value.disabled,
        'ScanTaskGroupId': value.scanTaskGroupId,
        'Event': value.event,
        'Name': value.name,
        'Scope': value.scope,
    };
}

