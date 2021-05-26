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
* Represents otp settings
*/
export class OtpSettings {
    /**
    * Gets or sets OtpType.
    */
    'otpType'?: OtpSettings.OtpTypeEnum;
    /**
    * Gets or sets secret key.
    */
    'secretKey'?: string;
    /**
    * Gets or sets digit.
    */
    'digit'?: OtpSettings.DigitEnum;
    /**
    * Gets or sets period (seconds).
    */
    'period'?: number;
    /**
    * Gets or sets hash algorithm.
    */
    'algorithm'?: OtpSettings.AlgorithmEnum;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "otpType",
            "baseName": "OtpType",
            "type": "OtpSettings.OtpTypeEnum"
        },
        {
            "name": "secretKey",
            "baseName": "SecretKey",
            "type": "string"
        },
        {
            "name": "digit",
            "baseName": "Digit",
            "type": "OtpSettings.DigitEnum"
        },
        {
            "name": "period",
            "baseName": "Period",
            "type": "number"
        },
        {
            "name": "algorithm",
            "baseName": "Algorithm",
            "type": "OtpSettings.AlgorithmEnum"
        }    ];

    static getAttributeTypeMap() {
        return OtpSettings.attributeTypeMap;
    }
}

export namespace OtpSettings {
    export enum OtpTypeEnum {
        Totp = <any> 'Totp',
        Hotp = <any> 'Hotp'
    }
    export enum DigitEnum {
        OtpDigit6 = <any> 'OtpDigit6',
        OtpDigit7 = <any> 'OtpDigit7',
        OtpDigit8 = <any> 'OtpDigit8'
    }
    export enum AlgorithmEnum {
        Sha1 = <any> 'Sha1',
        Sha256 = <any> 'Sha256',
        Sha512 = <any> 'Sha512'
    }
}
