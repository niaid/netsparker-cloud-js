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
import type { BasicAuthenticationCredentialModel } from './BasicAuthenticationCredentialModel';
import {
    BasicAuthenticationCredentialModelFromJSON,
    BasicAuthenticationCredentialModelFromJSONTyped,
    BasicAuthenticationCredentialModelToJSON,
} from './BasicAuthenticationCredentialModel';

/**
 * Represents a model for carrying out basic authentication settings.
 * @export
 * @interface BasicAuthenticationSettingModel
 */
export interface BasicAuthenticationSettingModel {
    /**
     * Gets or sets the authentication credentials.
     * @type {Array<BasicAuthenticationCredentialModel>}
     * @memberof BasicAuthenticationSettingModel
     */
    credentials?: Array<BasicAuthenticationCredentialModel>;
    /**
     * Gets or sets a value indicating whether basic authentication is enabled.
     * @type {boolean}
     * @memberof BasicAuthenticationSettingModel
     */
    isEnabled?: boolean;
    /**
     * Gets or sets a value indicating whether to send authentication headers without expecting a challenge.
     * @type {boolean}
     * @memberof BasicAuthenticationSettingModel
     */
    noChallenge?: boolean;
}

/**
 * Check if a given object implements the BasicAuthenticationSettingModel interface.
 */
export function instanceOfBasicAuthenticationSettingModel(value: object): boolean {
    return true;
}

export function BasicAuthenticationSettingModelFromJSON(json: any): BasicAuthenticationSettingModel {
    return BasicAuthenticationSettingModelFromJSONTyped(json, false);
}

export function BasicAuthenticationSettingModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): BasicAuthenticationSettingModel {
    if (json == null) {
        return json;
    }
    return {
        
        'credentials': json['Credentials'] == null ? undefined : ((json['Credentials'] as Array<any>).map(BasicAuthenticationCredentialModelFromJSON)),
        'isEnabled': json['IsEnabled'] == null ? undefined : json['IsEnabled'],
        'noChallenge': json['NoChallenge'] == null ? undefined : json['NoChallenge'],
    };
}

export function BasicAuthenticationSettingModelToJSON(value?: BasicAuthenticationSettingModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Credentials': value['credentials'] == null ? undefined : ((value['credentials'] as Array<any>).map(BasicAuthenticationCredentialModelToJSON)),
        'IsEnabled': value['isEnabled'],
        'NoChallenge': value['noChallenge'],
    };
}

