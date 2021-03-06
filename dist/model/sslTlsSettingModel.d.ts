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
* Represents SSL/TLS settings.
*/
export declare class SslTlsSettingModel {
    /**
    * Gets or sets invalid certificate action for the external domains.
    */
    'externalDomainInvalidCertificateAction'?: SslTlsSettingModel.ExternalDomainInvalidCertificateActionEnum;
    /**
    * Gets or sets a value indicating whether SSL v3 is enabled.
    */
    'ssl3Enabled'?: boolean;
    /**
    * Gets or sets invalid certificate action for the target URL.
    */
    'targetUrlInvalidCertificateAction'?: SslTlsSettingModel.TargetUrlInvalidCertificateActionEnum;
    /**
    * Gets or sets a value indicating whether TLS 1.0 is enabled.
    */
    'tls10Enabled'?: boolean;
    /**
    * Gets or sets a value indicating whether TLS 1.1 is enabled.
    */
    'tls11Enabled'?: boolean;
    /**
    * Gets or sets a value indicating whether TLS 1.2 is enabled.
    */
    'tls12Enabled'?: boolean;
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
export declare namespace SslTlsSettingModel {
    enum ExternalDomainInvalidCertificateActionEnum {
        Ignore,
        Reject
    }
    enum TargetUrlInvalidCertificateActionEnum {
        Ignore,
        Reject
    }
}
