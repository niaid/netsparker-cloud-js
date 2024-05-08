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
import type { BasicAuthenticationCredentialApiModel } from './BasicAuthenticationCredentialApiModel';
import {
    BasicAuthenticationCredentialApiModelFromJSON,
    BasicAuthenticationCredentialApiModelFromJSONTyped,
    BasicAuthenticationCredentialApiModelToJSON,
} from './BasicAuthenticationCredentialApiModel';

/**
 * Provides credentials for NTLM, Basic, Kerberos, Digest or Negotiate authentication schemes.
 * @export
 * @interface BasicAuthenticationSettingApiModel
 */
export interface BasicAuthenticationSettingApiModel {
    /**
     * Gets or sets a value indicating whether to send authentication headers without expecting a challenge.
     * @type {boolean}
     * @memberof BasicAuthenticationSettingApiModel
     */
    alwaysAuthenticateNoChallenge?: boolean;
    /**
     * Gets or sets the authentication credentials.
     * @type {Array<BasicAuthenticationCredentialApiModel>}
     * @memberof BasicAuthenticationSettingApiModel
     */
    credentials?: Array<BasicAuthenticationCredentialApiModel>;
}

/**
 * Check if a given object implements the BasicAuthenticationSettingApiModel interface.
 */
export function instanceOfBasicAuthenticationSettingApiModel(value: object): boolean {
    return true;
}

export function BasicAuthenticationSettingApiModelFromJSON(json: any): BasicAuthenticationSettingApiModel {
    return BasicAuthenticationSettingApiModelFromJSONTyped(json, false);
}

export function BasicAuthenticationSettingApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): BasicAuthenticationSettingApiModel {
    if (json == null) {
        return json;
    }
    return {
        
        'alwaysAuthenticateNoChallenge': json['AlwaysAuthenticateNoChallenge'] == null ? undefined : json['AlwaysAuthenticateNoChallenge'],
        'credentials': json['Credentials'] == null ? undefined : ((json['Credentials'] as Array<any>).map(BasicAuthenticationCredentialApiModelFromJSON)),
    };
}

export function BasicAuthenticationSettingApiModelToJSON(value?: BasicAuthenticationSettingApiModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'AlwaysAuthenticateNoChallenge': value['alwaysAuthenticateNoChallenge'],
        'Credentials': value['credentials'] == null ? undefined : ((value['credentials'] as Array<any>).map(BasicAuthenticationCredentialApiModelToJSON)),
    };
}

