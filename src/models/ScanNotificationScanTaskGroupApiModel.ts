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
/**
 * Represents a model for scan notification api model
 * @export
 * @interface ScanNotificationScanTaskGroupApiModel
 */
export interface ScanNotificationScanTaskGroupApiModel {
    /**
     * Gets or sets the website id
     * @type {string}
     * @memberof ScanNotificationScanTaskGroupApiModel
     */
    websiteId?: string;
    /**
     * Gets or sets the scan task group name
     * @type {string}
     * @memberof ScanNotificationScanTaskGroupApiModel
     */
    scanTaskGroupName?: string;
    /**
     * Gets or sets the scan task group id
     * @type {string}
     * @memberof ScanNotificationScanTaskGroupApiModel
     */
    scanTaskGroupId?: string;
}

/**
 * Check if a given object implements the ScanNotificationScanTaskGroupApiModel interface.
 */
export function instanceOfScanNotificationScanTaskGroupApiModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function ScanNotificationScanTaskGroupApiModelFromJSON(json: any): ScanNotificationScanTaskGroupApiModel {
    return ScanNotificationScanTaskGroupApiModelFromJSONTyped(json, false);
}

export function ScanNotificationScanTaskGroupApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanNotificationScanTaskGroupApiModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'websiteId': !exists(json, 'WebsiteId') ? undefined : json['WebsiteId'],
        'scanTaskGroupName': !exists(json, 'ScanTaskGroupName') ? undefined : json['ScanTaskGroupName'],
        'scanTaskGroupId': !exists(json, 'ScanTaskGroupId') ? undefined : json['ScanTaskGroupId'],
    };
}

export function ScanNotificationScanTaskGroupApiModelToJSON(value?: ScanNotificationScanTaskGroupApiModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'WebsiteId': value.websiteId,
        'ScanTaskGroupName': value.scanTaskGroupName,
        'ScanTaskGroupId': value.scanTaskGroupId,
    };
}

