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
import { ApiFileModel } from './apiFileModel';

/**
* Represents a model for carrying out client certificate authentication settings.
*/
export class ClientCertificateAuthenticationApiModel {
    'file': ApiFileModel;
    /**
    * Gets or sets a value indicating whether client certificate authentication is enabled.
    */
    'isEnabled'?: boolean;
    /**
    * Gets or sets the password for client certificate authentication.
    */
    'password'?: string;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "file",
            "baseName": "File",
            "type": "ApiFileModel"
        },
        {
            "name": "isEnabled",
            "baseName": "IsEnabled",
            "type": "boolean"
        },
        {
            "name": "password",
            "baseName": "Password",
            "type": "string"
        }    ];

    static getAttributeTypeMap() {
        return ClientCertificateAuthenticationApiModel.attributeTypeMap;
    }
}

