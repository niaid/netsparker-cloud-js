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
 * Represents a model for exclude/include link setting.
 * @export
 * @interface ExcludedUsageTrackerModel
 */
export interface ExcludedUsageTrackerModel {
    /**
     * Gets or sets the pattern.
     * @type {string}
     * @memberof ExcludedUsageTrackerModel
     */
    url: string;
}

/**
 * Check if a given object implements the ExcludedUsageTrackerModel interface.
 */
export function instanceOfExcludedUsageTrackerModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "url" in value;

    return isInstance;
}

export function ExcludedUsageTrackerModelFromJSON(json: any): ExcludedUsageTrackerModel {
    return ExcludedUsageTrackerModelFromJSONTyped(json, false);
}

export function ExcludedUsageTrackerModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ExcludedUsageTrackerModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'url': json['Url'],
    };
}

export function ExcludedUsageTrackerModelToJSON(value?: ExcludedUsageTrackerModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Url': value.url,
    };
}

