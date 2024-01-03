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
import type { ScanTimeWindowItemModel } from './ScanTimeWindowItemModel';
import {
    ScanTimeWindowItemModelFromJSON,
    ScanTimeWindowItemModelFromJSONTyped,
    ScanTimeWindowItemModelToJSON,
} from './ScanTimeWindowItemModel';

/**
 * 
 * @export
 * @interface ScanTimeWindowModel
 */
export interface ScanTimeWindowModel {
    /**
     * 
     * @type {Array<ScanTimeWindowItemModel>}
     * @memberof ScanTimeWindowModel
     */
    items?: Array<ScanTimeWindowItemModel>;
}

/**
 * Check if a given object implements the ScanTimeWindowModel interface.
 */
export function instanceOfScanTimeWindowModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function ScanTimeWindowModelFromJSON(json: any): ScanTimeWindowModel {
    return ScanTimeWindowModelFromJSONTyped(json, false);
}

export function ScanTimeWindowModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanTimeWindowModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'items': !exists(json, 'Items') ? undefined : ((json['Items'] as Array<any>).map(ScanTimeWindowItemModelFromJSON)),
    };
}

export function ScanTimeWindowModelToJSON(value?: ScanTimeWindowModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Items': value.items === undefined ? undefined : ((value.items as Array<any>).map(ScanTimeWindowItemModelToJSON)),
    };
}

