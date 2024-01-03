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
 * Represents credentials for Basic, NTML, Kerberos, Digest or Negotiate authentication.
 * @export
 * @interface BasicAuthenticationCredentialModel
 */
export interface BasicAuthenticationCredentialModel {
    /**
     * Gets or sets the type of the authentication.
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    authenticationType?: BasicAuthenticationCredentialModelAuthenticationTypeEnum;
    /**
     * Gets or sets the domain for basic authentication.
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    domain?: string;
    /**
     * Gets or sets the password for basic authentication.
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    password: string;
    /**
     * Gets or sets the URI prefix.
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    uriPrefix: string;
    /**
     * Gets or sets the user name for basic authentication.
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    userName: string;
    /**
     * Gets or sets the URI prefix that not modified by user on client side.
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    originalUriPrefix?: string;
    /**
     * Gets or sets the user name for basic authentication that not modified by user on client side.
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    originalUserName?: string;
    /**
     * Encrypted original password
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    originalPassword?: string;
    /**
     * Gets or sets a value indicating whether the placeholders is replaced with actual credentials.
     * @type {boolean}
     * @memberof BasicAuthenticationCredentialModel
     */
    isReplacedCredentials?: boolean;
}

/**
* @export
* @enum {string}
*/
export enum BasicAuthenticationCredentialModelAuthenticationTypeEnum {
    Basic = 'Basic',
    Ntlm = 'Ntlm',
    Kerberos = 'Kerberos',
    Digest = 'Digest',
    Negotiate = 'Negotiate'
}


/**
 * Check if a given object implements the BasicAuthenticationCredentialModel interface.
 */
export function instanceOfBasicAuthenticationCredentialModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "password" in value;
    isInstance = isInstance && "uriPrefix" in value;
    isInstance = isInstance && "userName" in value;

    return isInstance;
}

export function BasicAuthenticationCredentialModelFromJSON(json: any): BasicAuthenticationCredentialModel {
    return BasicAuthenticationCredentialModelFromJSONTyped(json, false);
}

export function BasicAuthenticationCredentialModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): BasicAuthenticationCredentialModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'authenticationType': !exists(json, 'AuthenticationType') ? undefined : json['AuthenticationType'],
        'domain': !exists(json, 'Domain') ? undefined : json['Domain'],
        'password': json['Password'],
        'uriPrefix': json['UriPrefix'],
        'userName': json['UserName'],
        'originalUriPrefix': !exists(json, 'OriginalUriPrefix') ? undefined : json['OriginalUriPrefix'],
        'originalUserName': !exists(json, 'OriginalUserName') ? undefined : json['OriginalUserName'],
        'originalPassword': !exists(json, 'OriginalPassword') ? undefined : json['OriginalPassword'],
        'isReplacedCredentials': !exists(json, 'IsReplacedCredentials') ? undefined : json['IsReplacedCredentials'],
    };
}

export function BasicAuthenticationCredentialModelToJSON(value?: BasicAuthenticationCredentialModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'AuthenticationType': value.authenticationType,
        'Domain': value.domain,
        'Password': value.password,
        'UriPrefix': value.uriPrefix,
        'UserName': value.userName,
        'OriginalUriPrefix': value.originalUriPrefix,
        'OriginalUserName': value.originalUserName,
        'OriginalPassword': value.originalPassword,
        'IsReplacedCredentials': value.isReplacedCredentials,
    };
}

