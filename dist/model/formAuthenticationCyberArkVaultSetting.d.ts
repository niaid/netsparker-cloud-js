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
* Settings of user\'s cyberark vault
*/
export declare class FormAuthenticationCyberArkVaultSetting {
    /**
    * Gets or sets the integration id.
    */
    'integrationId'?: string;
    /**
    * Gets or sets the username is static or not.
    */
    'cyberArkUseStaticUsername'?: boolean;
    /**
    * Gets or sets the Static Username.
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
