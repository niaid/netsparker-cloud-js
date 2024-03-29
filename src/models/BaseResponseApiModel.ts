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
 * The class using for response api models.
 * @export
 * @interface BaseResponseApiModel
 */
export interface BaseResponseApiModel {
    /**
     * Gets or sets the message field.
     * @type {string}
     * @memberof BaseResponseApiModel
     */
    message?: string;
}

/**
 * Check if a given object implements the BaseResponseApiModel interface.
 */
export function instanceOfBaseResponseApiModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function BaseResponseApiModelFromJSON(json: any): BaseResponseApiModel {
    return BaseResponseApiModelFromJSONTyped(json, false);
}

export function BaseResponseApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): BaseResponseApiModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'message': !exists(json, 'Message') ? undefined : json['Message'],
    };
}

export function BaseResponseApiModelToJSON(value?: BaseResponseApiModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Message': value.message,
    };
}

