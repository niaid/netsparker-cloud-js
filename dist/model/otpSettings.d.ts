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
/**
* Represents otp settings
*/
export declare class OtpSettings {
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
export declare namespace OtpSettings {
    enum OtpTypeEnum {
        Totp,
        Hotp
    }
    enum DigitEnum {
        OtpDigit6,
        OtpDigit7,
        OtpDigit8
    }
    enum AlgorithmEnum {
        Sha1,
        Sha256,
        Sha512
    }
}
