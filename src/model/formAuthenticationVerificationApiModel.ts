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
import { OtpSettings } from './otpSettings';

/**
* Represents a form authentication verification model.
*/
export class FormAuthenticationVerificationApiModel {
    /**
    * Gets or sets the login form URL.
    */
    'loginFormUrl': string;
    /**
    * Gets or sets the password.
    */
    'password': string;
    /**
    * Gets or sets the scan target URL.
    */
    'scanTargetUrl': string;
    /**
    * Gets or sets the user name.
    */
    'username': string;
    'otpSettings'?: OtpSettings;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "loginFormUrl",
            "baseName": "LoginFormUrl",
            "type": "string"
        },
        {
            "name": "password",
            "baseName": "Password",
            "type": "string"
        },
        {
            "name": "scanTargetUrl",
            "baseName": "ScanTargetUrl",
            "type": "string"
        },
        {
            "name": "username",
            "baseName": "Username",
            "type": "string"
        },
        {
            "name": "otpSettings",
            "baseName": "OtpSettings",
            "type": "OtpSettings"
        }    ];

    static getAttributeTypeMap() {
        return FormAuthenticationVerificationApiModel.attributeTypeMap;
    }
}
