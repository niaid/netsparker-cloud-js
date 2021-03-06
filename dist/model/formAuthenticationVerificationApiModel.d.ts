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
import { OtpSettings } from './otpSettings';
/**
* Represents a form authentication verification model.
*/
export declare class FormAuthenticationVerificationApiModel {
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
    static discriminator: string | undefined;
    static attributeTypeMap: Array<{
        name: string;
        baseName: string;
        type: string;
    }>;
    static getAttributeTypeMap(): {
        name: string;
        baseName: string;
        type: string;
    }[];
}
