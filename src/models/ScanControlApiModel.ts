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
 * 
 * @export
 * @interface ScanControlApiModel
 */
export interface ScanControlApiModel {
    /**
     * 
     * @type {boolean}
     * @memberof ScanControlApiModel
     */
    isScansSuspended?: boolean;
}

/**
 * Check if a given object implements the ScanControlApiModel interface.
 */
export function instanceOfScanControlApiModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function ScanControlApiModelFromJSON(json: any): ScanControlApiModel {
    return ScanControlApiModelFromJSONTyped(json, false);
}

export function ScanControlApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanControlApiModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'isScansSuspended': !exists(json, 'IsScansSuspended') ? undefined : json['IsScansSuspended'],
    };
}

export function ScanControlApiModelToJSON(value?: ScanControlApiModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'IsScansSuspended': value.isScansSuspended,
    };
}
