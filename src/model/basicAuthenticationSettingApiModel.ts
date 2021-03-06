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

import { RequestFile } from './models';
import { BasicAuthenticationCredentialApiModel } from './basicAuthenticationCredentialApiModel';

/**
* Provides credentials for NTLM, Basic, Kerberos, Digest or Negotiate authentication schemes.
*/
export class BasicAuthenticationSettingApiModel {
    /**
    * Gets or sets a value indicating whether to send authentication headers without expecting a challenge.
    */
    'alwaysAuthenticateNoChallenge'?: boolean;
    /**
    * Gets or sets the authentication credentials.
    */
    'credentials'?: Array<BasicAuthenticationCredentialApiModel>;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "alwaysAuthenticateNoChallenge",
            "baseName": "AlwaysAuthenticateNoChallenge",
            "type": "boolean"
        },
        {
            "name": "credentials",
            "baseName": "Credentials",
            "type": "Array<BasicAuthenticationCredentialApiModel>"
        }    ];

    static getAttributeTypeMap() {
        return BasicAuthenticationSettingApiModel.attributeTypeMap;
    }
}

