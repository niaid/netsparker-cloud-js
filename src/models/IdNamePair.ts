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
 * Represents the Id and Name pair
 * @export
 * @interface IdNamePair
 */
export interface IdNamePair {
    /**
     * Gets or sets id
     * @type {string}
     * @memberof IdNamePair
     */
    id?: string;
    /**
     * Gets or sets name
     * @type {string}
     * @memberof IdNamePair
     */
    name?: string;
}

/**
 * Check if a given object implements the IdNamePair interface.
 */
export function instanceOfIdNamePair(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function IdNamePairFromJSON(json: any): IdNamePair {
    return IdNamePairFromJSONTyped(json, false);
}

export function IdNamePairFromJSONTyped(json: any, ignoreDiscriminator: boolean): IdNamePair {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'id': !exists(json, 'Id') ? undefined : json['Id'],
        'name': !exists(json, 'Name') ? undefined : json['Name'],
    };
}

export function IdNamePairToJSON(value?: IdNamePair | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Id': value.id,
        'Name': value.name,
    };
}

