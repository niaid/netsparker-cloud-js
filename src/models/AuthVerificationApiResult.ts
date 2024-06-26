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
 * @interface AuthVerificationApiResult
 */
export interface AuthVerificationApiResult {
    /**
     * Gets or sets the suggested logout keywords.
     * @type {Array<string>}
     * @memberof AuthVerificationApiResult
     */
    keywords?: Array<string>;
    /**
     * Gets or sets the login required URL.
     * @type {string}
     * @memberof AuthVerificationApiResult
     */
    loginRequiredUrl?: string;
    /**
     * Gets or sets the type of the logout signature.
     * @type {string}
     * @memberof AuthVerificationApiResult
     */
    logoutSignatureType?: AuthVerificationApiResultLogoutSignatureTypeEnum;
    /**
     * Gets or sets the redirect location.
     * @type {string}
     * @memberof AuthVerificationApiResult
     */
    redirectLocation?: string;
}


/**
 * @export
 */
export const AuthVerificationApiResultLogoutSignatureTypeEnum = {
    None: 'None',
    RedirectBased: 'RedirectBased',
    KeywordBased: 'KeywordBased'
} as const;
export type AuthVerificationApiResultLogoutSignatureTypeEnum = typeof AuthVerificationApiResultLogoutSignatureTypeEnum[keyof typeof AuthVerificationApiResultLogoutSignatureTypeEnum];


/**
 * Check if a given object implements the AuthVerificationApiResult interface.
 */
export function instanceOfAuthVerificationApiResult(value: object): boolean {
    return true;
}

export function AuthVerificationApiResultFromJSON(json: any): AuthVerificationApiResult {
    return AuthVerificationApiResultFromJSONTyped(json, false);
}

export function AuthVerificationApiResultFromJSONTyped(json: any, ignoreDiscriminator: boolean): AuthVerificationApiResult {
    if (json == null) {
        return json;
    }
    return {
        
        'keywords': json['Keywords'] == null ? undefined : json['Keywords'],
        'loginRequiredUrl': json['LoginRequiredUrl'] == null ? undefined : json['LoginRequiredUrl'],
        'logoutSignatureType': json['LogoutSignatureType'] == null ? undefined : json['LogoutSignatureType'],
        'redirectLocation': json['RedirectLocation'] == null ? undefined : json['RedirectLocation'],
    };
}

export function AuthVerificationApiResultToJSON(value?: AuthVerificationApiResult | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Keywords': value['keywords'],
        'LoginRequiredUrl': value['loginRequiredUrl'],
        'LogoutSignatureType': value['logoutSignatureType'],
        'RedirectLocation': value['redirectLocation'],
    };
}

