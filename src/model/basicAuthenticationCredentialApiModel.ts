/**
 * Netsparker Enterprise API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: v1
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { RequestFile } from './models';

/**
* Represents credentials for Basic, NTML, Kerberos, Digest or Negotiate authentication.
*/
export class BasicAuthenticationCredentialApiModel {
    /**
    * Gets or sets the type of the authentication.
    */
    'authenticationType'?: BasicAuthenticationCredentialApiModel.AuthenticationTypeEnum;
    /**
    * Gets or sets the domain or computer name that verifies the credentials.
    */
    'domain'?: string;
    /**
    * Gets or sets the password for the user name associated with the credentials.
    */
    'password'?: string;
    /**
    * Gets or sets the URI prefix.
    */
    'uriPrefix'?: string;
    /**
    * Gets or sets the user name associated with the credentials.
    */
    'userName'?: string;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "authenticationType",
            "baseName": "AuthenticationType",
            "type": "BasicAuthenticationCredentialApiModel.AuthenticationTypeEnum"
        },
        {
            "name": "domain",
            "baseName": "Domain",
            "type": "string"
        },
        {
            "name": "password",
            "baseName": "Password",
            "type": "string"
        },
        {
            "name": "uriPrefix",
            "baseName": "UriPrefix",
            "type": "string"
        },
        {
            "name": "userName",
            "baseName": "UserName",
            "type": "string"
        }    ];

    static getAttributeTypeMap() {
        return BasicAuthenticationCredentialApiModel.attributeTypeMap;
    }
}

export namespace BasicAuthenticationCredentialApiModel {
    export enum AuthenticationTypeEnum {
        Basic = <any> 'Basic',
        Ntlm = <any> 'Ntlm',
        Kerberos = <any> 'Kerberos',
        Digest = <any> 'Digest',
        Negotiate = <any> 'Negotiate'
    }
}
