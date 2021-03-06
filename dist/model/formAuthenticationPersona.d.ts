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
* Represents a Form Authentication persona.
*/
export declare class FormAuthenticationPersona {
    /**
    * Gets or sets a value indicating whether this persona is the active one to use for a scan.
    */
    'isActive'?: boolean;
    /**
    * Gets or sets the password.
    */
    'password'?: string;
    /**
    * Gets or sets the user name.
    */
    'userName': string;
    /**
    * Gets or sets OtpType.
    */
    'otpType'?: FormAuthenticationPersona.OtpTypeEnum;
    /**
    * Gets or sets secret key.
    */
    'secretKey'?: string;
    /**
    * Gets or sets digit.
    */
    'digit'?: FormAuthenticationPersona.DigitEnum;
    /**
    * Gets or sets period (seconds).
    */
    'period'?: number;
    /**
    * Gets or sets hash algorithm.
    */
    'algorithm'?: FormAuthenticationPersona.AlgorithmEnum;
    /**
    * Gets or sets the type of form authentication.
    */
    'formAuthType'?: FormAuthenticationPersona.FormAuthTypeEnum;
    /**
    * Gets or sets the integration id.
    */
    'integrationId'?: string;
    /**
    * Gets or sets the KV Secret engine version.
    */
    'version'?: FormAuthenticationPersona.VersionEnum;
    /**
    * Gets or sets the secret engine.
    */
    'secretEngine'?: string;
    /**
    * Gets or sets the secret.
    */
    'secret'?: string;
    /**
    * Gets or sets the username is static or not.
    */
    'useStaticUsername'?: boolean;
    /**
    * Gets or sets the static username.
    */
    'staticUsername'?: string;
    /**
    * Gets or sets the username key.
    */
    'usernameKey'?: string;
    /**
    * Gets or sets the password key.
    */
    'passwordKey'?: string;
    /**
    * Gets or sets the username is static or not.
    */
    'cyberArkUseStaticUsername'?: boolean;
    /**
    * Gets or sets the AppID.
    */
    'cyberArkStaticUsername'?: string;
    /**
    * Gets or sets the Query.
    */
    'cyberArkUserNameQuery'?: string;
    /**
    * Gets or sets the Query.
    */
    'cyberArkPasswordQuery'?: string;
    /**
    * Gets or sets the user name that not modified by user on client side.
    */
    'originalUserName'?: string;
    /**
    * Gets or sets a value indicating whether the placeholders is replaced with actual credentials.
    */
    'isReplacedCredentials'?: boolean;
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
export declare namespace FormAuthenticationPersona {
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
    enum FormAuthTypeEnum {
        Manual,
        Integration
    }
    enum VersionEnum {
        V1,
        V2
    }
}
