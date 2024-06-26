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
 * Represents a model for shark setting
 * @export
 * @interface SharkModel
 */
export interface SharkModel {
    /**
     * Gets or sets is Shark/Sensor enabled
     * @type {boolean}
     * @memberof SharkModel
     */
    isSharkEnabled?: boolean;
    /**
     * Gets or sets a value indicating backend-platform type.
     * @type {string}
     * @memberof SharkModel
     */
    sharkPlatformType?: SharkModelSharkPlatformTypeEnum;
    /**
     * Gets or sets the generated Shark/Sensor password
     * @type {string}
     * @memberof SharkModel
     */
    sharkPassword?: string;
    /**
     * 
     * @type {string}
     * @memberof SharkModel
     */
    sharkBridgeUrl?: string;
}


/**
 * @export
 */
export const SharkModelSharkPlatformTypeEnum = {
    AspNet: 'AspNet',
    Php: 'Php',
    Java: 'Java',
    NodeJs: 'NodeJs'
} as const;
export type SharkModelSharkPlatformTypeEnum = typeof SharkModelSharkPlatformTypeEnum[keyof typeof SharkModelSharkPlatformTypeEnum];


/**
 * Check if a given object implements the SharkModel interface.
 */
export function instanceOfSharkModel(value: object): boolean {
    return true;
}

export function SharkModelFromJSON(json: any): SharkModel {
    return SharkModelFromJSONTyped(json, false);
}

export function SharkModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): SharkModel {
    if (json == null) {
        return json;
    }
    return {
        
        'isSharkEnabled': json['IsSharkEnabled'] == null ? undefined : json['IsSharkEnabled'],
        'sharkPlatformType': json['SharkPlatformType'] == null ? undefined : json['SharkPlatformType'],
        'sharkPassword': json['SharkPassword'] == null ? undefined : json['SharkPassword'],
        'sharkBridgeUrl': json['SharkBridgeUrl'] == null ? undefined : json['SharkBridgeUrl'],
    };
}

export function SharkModelToJSON(value?: SharkModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'IsSharkEnabled': value['isSharkEnabled'],
        'SharkPlatformType': value['sharkPlatformType'],
        'SharkPassword': value['sharkPassword'],
        'SharkBridgeUrl': value['sharkBridgeUrl'],
    };
}

