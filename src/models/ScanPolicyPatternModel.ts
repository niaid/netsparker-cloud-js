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
 * Represents a model for carrying out pattern settings.
 * @export
 * @interface ScanPolicyPatternModel
 */
export interface ScanPolicyPatternModel {
    /**
     * Gets or sets the id of the custom script id.
     * @type {string}
     * @memberof ScanPolicyPatternModel
     */
    customScriptId?: string;
    /**
     * Gets or sets the description of the security check.
     * @type {string}
     * @memberof ScanPolicyPatternModel
     */
    description?: string;
    /**
     * Gets or sets a value indicating whether this instance is enabled.
     * @type {boolean}
     * @memberof ScanPolicyPatternModel
     */
    enabled?: boolean;
    /**
     * Gets or sets the id of the security check.
     * @type {string}
     * @memberof ScanPolicyPatternModel
     */
    id?: string;
    /**
     * Gets or sets the name of the security check.
     * @type {string}
     * @memberof ScanPolicyPatternModel
     */
    name?: string;
}

/**
 * Check if a given object implements the ScanPolicyPatternModel interface.
 */
export function instanceOfScanPolicyPatternModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function ScanPolicyPatternModelFromJSON(json: any): ScanPolicyPatternModel {
    return ScanPolicyPatternModelFromJSONTyped(json, false);
}

export function ScanPolicyPatternModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanPolicyPatternModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'customScriptId': !exists(json, 'CustomScriptId') ? undefined : json['CustomScriptId'],
        'description': !exists(json, 'Description') ? undefined : json['Description'],
        'enabled': !exists(json, 'Enabled') ? undefined : json['Enabled'],
        'id': !exists(json, 'Id') ? undefined : json['Id'],
        'name': !exists(json, 'Name') ? undefined : json['Name'],
    };
}

export function ScanPolicyPatternModelToJSON(value?: ScanPolicyPatternModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'CustomScriptId': value.customScriptId,
        'Description': value.description,
        'Enabled': value.enabled,
        'Id': value.id,
        'Name': value.name,
    };
}

