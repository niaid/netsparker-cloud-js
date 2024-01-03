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
import type { NameValuePair } from './NameValuePair';
import {
    NameValuePairFromJSON,
    NameValuePairFromJSONTyped,
    NameValuePairToJSON,
} from './NameValuePair';

/**
 * Represents authorization code table model for oauth2.
 * @export
 * @interface AuthorizationCodeTableModel
 */
export interface AuthorizationCodeTableModel {
    /**
     * Gets or sets the table column names.
     * @type {Array<string>}
     * @memberof AuthorizationCodeTableModel
     */
    fields?: Array<string>;
    /**
     * Gets or sets the authorization code table items.
     * @type {Array<NameValuePair>}
     * @memberof AuthorizationCodeTableModel
     */
    items?: Array<NameValuePair>;
}

/**
 * Check if a given object implements the AuthorizationCodeTableModel interface.
 */
export function instanceOfAuthorizationCodeTableModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function AuthorizationCodeTableModelFromJSON(json: any): AuthorizationCodeTableModel {
    return AuthorizationCodeTableModelFromJSONTyped(json, false);
}

export function AuthorizationCodeTableModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AuthorizationCodeTableModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'fields': !exists(json, 'Fields') ? undefined : json['Fields'],
        'items': !exists(json, 'Items') ? undefined : ((json['Items'] as Array<any>).map(NameValuePairFromJSON)),
    };
}

export function AuthorizationCodeTableModelToJSON(value?: AuthorizationCodeTableModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Fields': value.fields,
        'Items': value.items === undefined ? undefined : ((value.items as Array<any>).map(NameValuePairToJSON)),
    };
}

