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
 * Represents a model for carrying out a delete scan notification data
 * @export
 * @interface DeleteScanNotificationApiModel
 */
export interface DeleteScanNotificationApiModel {
    /**
     * Gets or sets the scan notification identifier.
     * @type {string}
     * @memberof DeleteScanNotificationApiModel
     */
    id: string;
}

/**
 * Check if a given object implements the DeleteScanNotificationApiModel interface.
 */
export function instanceOfDeleteScanNotificationApiModel(value: object): boolean {
    if (!('id' in value)) return false;
    return true;
}

export function DeleteScanNotificationApiModelFromJSON(json: any): DeleteScanNotificationApiModel {
    return DeleteScanNotificationApiModelFromJSONTyped(json, false);
}

export function DeleteScanNotificationApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): DeleteScanNotificationApiModel {
    if (json == null) {
        return json;
    }
    return {
        
        'id': json['Id'],
    };
}

export function DeleteScanNotificationApiModelToJSON(value?: DeleteScanNotificationApiModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Id': value['id'],
    };
}

