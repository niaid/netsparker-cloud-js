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
 * 
 * @export
 * @interface AsanaWorkspace
 */
export interface AsanaWorkspace {
    /**
     * 
     * @type {string}
     * @memberof AsanaWorkspace
     */
    gid?: string;
    /**
     * 
     * @type {string}
     * @memberof AsanaWorkspace
     */
    name?: string;
}

/**
 * Check if a given object implements the AsanaWorkspace interface.
 */
export function instanceOfAsanaWorkspace(value: object): boolean {
    return true;
}

export function AsanaWorkspaceFromJSON(json: any): AsanaWorkspace {
    return AsanaWorkspaceFromJSONTyped(json, false);
}

export function AsanaWorkspaceFromJSONTyped(json: any, ignoreDiscriminator: boolean): AsanaWorkspace {
    if (json == null) {
        return json;
    }
    return {
        
        'gid': json['gid'] == null ? undefined : json['gid'],
        'name': json['name'] == null ? undefined : json['name'],
    };
}

export function AsanaWorkspaceToJSON(value?: AsanaWorkspace | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'gid': value['gid'],
        'name': value['name'],
    };
}

