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
 * Represents a model for carrying out a logout keyword pattern.
 * @export
 * @interface LogoutKeywordPatternModel
 */
export interface LogoutKeywordPatternModel {
    /**
     * Gets or sets the pattern.
     * @type {string}
     * @memberof LogoutKeywordPatternModel
     */
    pattern: string;
    /**
     * Gets or sets a value indicating whether this is regex.
     * @type {boolean}
     * @memberof LogoutKeywordPatternModel
     */
    regex?: boolean;
}

/**
 * Check if a given object implements the LogoutKeywordPatternModel interface.
 */
export function instanceOfLogoutKeywordPatternModel(value: object): boolean {
    if (!('pattern' in value)) return false;
    return true;
}

export function LogoutKeywordPatternModelFromJSON(json: any): LogoutKeywordPatternModel {
    return LogoutKeywordPatternModelFromJSONTyped(json, false);
}

export function LogoutKeywordPatternModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): LogoutKeywordPatternModel {
    if (json == null) {
        return json;
    }
    return {
        
        'pattern': json['Pattern'],
        'regex': json['Regex'] == null ? undefined : json['Regex'],
    };
}

export function LogoutKeywordPatternModelToJSON(value?: LogoutKeywordPatternModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Pattern': value['pattern'],
        'Regex': value['regex'],
    };
}

