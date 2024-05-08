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
/**
 * Represents a notification priority pair
 * @export
 * @interface NotificationPriorityPair
 */
export interface NotificationPriorityPair {
    /**
     * Gets or sets the identifier.
     * @type {string}
     * @memberof NotificationPriorityPair
     */
    id?: string;
    /**
     * Gets or sets the priority.
     * @type {number}
     * @memberof NotificationPriorityPair
     */
    priority?: number;
}

/**
 * Check if a given object implements the NotificationPriorityPair interface.
 */
export function instanceOfNotificationPriorityPair(value: object): boolean {
    return true;
}

export function NotificationPriorityPairFromJSON(json: any): NotificationPriorityPair {
    return NotificationPriorityPairFromJSONTyped(json, false);
}

export function NotificationPriorityPairFromJSONTyped(json: any, ignoreDiscriminator: boolean): NotificationPriorityPair {
    if (json == null) {
        return json;
    }
    return {
        
        'id': json['Id'] == null ? undefined : json['Id'],
        'priority': json['Priority'] == null ? undefined : json['Priority'],
    };
}

export function NotificationPriorityPairToJSON(value?: NotificationPriorityPair | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Id': value['id'],
        'Priority': value['priority'],
    };
}

