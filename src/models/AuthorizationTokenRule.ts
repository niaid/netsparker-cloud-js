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
 * @interface AuthorizationTokenRule
 */
export interface AuthorizationTokenRule {
    /**
     * Gets or sets the source URL.
     * @type {string}
     * @memberof AuthorizationTokenRule
     */
    source?: string;
    /**
     * Gets or sets the target URL.
     * @type {string}
     * @memberof AuthorizationTokenRule
     */
    destination?: string;
}

/**
 * Check if a given object implements the AuthorizationTokenRule interface.
 */
export function instanceOfAuthorizationTokenRule(value: object): boolean {
    return true;
}

export function AuthorizationTokenRuleFromJSON(json: any): AuthorizationTokenRule {
    return AuthorizationTokenRuleFromJSONTyped(json, false);
}

export function AuthorizationTokenRuleFromJSONTyped(json: any, ignoreDiscriminator: boolean): AuthorizationTokenRule {
    if (json == null) {
        return json;
    }
    return {
        
        'source': json['Source'] == null ? undefined : json['Source'],
        'destination': json['Destination'] == null ? undefined : json['Destination'],
    };
}

export function AuthorizationTokenRuleToJSON(value?: AuthorizationTokenRule | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Source': value['source'],
        'Destination': value['destination'],
    };
}

