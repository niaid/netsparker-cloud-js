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
/**
 * Settings of user's cyberark vault
 * @export
 * @interface FormAuthenticationCyberArkVaultSetting
 */
export interface FormAuthenticationCyberArkVaultSetting {
    /**
     * Gets or sets the integration id.
     * @type {string}
     * @memberof FormAuthenticationCyberArkVaultSetting
     */
    integrationId?: string;
    /**
     * Gets or sets the username is static or not.
     * @type {boolean}
     * @memberof FormAuthenticationCyberArkVaultSetting
     */
    cyberArkUseStaticUsername?: boolean;
    /**
     * Gets or sets the Static Username.
     * @type {string}
     * @memberof FormAuthenticationCyberArkVaultSetting
     */
    cyberArkStaticUsername?: string;
    /**
     * Gets or sets the Query.
     * @type {string}
     * @memberof FormAuthenticationCyberArkVaultSetting
     */
    cyberArkUserNameQuery?: string;
    /**
     * Gets or sets the Query.
     * @type {string}
     * @memberof FormAuthenticationCyberArkVaultSetting
     */
    cyberArkPasswordQuery?: string;
    /**
     * Gets or sets the Url.
     * @type {string}
     * @memberof FormAuthenticationCyberArkVaultSetting
     */
    url?: string;
    /**
     *
     * @type {string}
     * @memberof FormAuthenticationCyberArkVaultSetting
     */
    certificateFilePassword?: string;
    /**
     *
     * @type {string}
     * @memberof FormAuthenticationCyberArkVaultSetting
     */
    certificateFileKey?: string;
    /**
     * Gets or sets website agent mode.
     * @type {string}
     * @memberof FormAuthenticationCyberArkVaultSetting
     */
    agentMode?: FormAuthenticationCyberArkVaultSettingAgentModeEnum;
}
/**
 * @export
 */
export declare const FormAuthenticationCyberArkVaultSettingAgentModeEnum: {
    readonly Cloud: "Cloud";
    readonly Internal: "Internal";
};
export type FormAuthenticationCyberArkVaultSettingAgentModeEnum = typeof FormAuthenticationCyberArkVaultSettingAgentModeEnum[keyof typeof FormAuthenticationCyberArkVaultSettingAgentModeEnum];
/**
 * Check if a given object implements the FormAuthenticationCyberArkVaultSetting interface.
 */
export declare function instanceOfFormAuthenticationCyberArkVaultSetting(value: object): boolean;
export declare function FormAuthenticationCyberArkVaultSettingFromJSON(json: any): FormAuthenticationCyberArkVaultSetting;
export declare function FormAuthenticationCyberArkVaultSettingFromJSONTyped(json: any, ignoreDiscriminator: boolean): FormAuthenticationCyberArkVaultSetting;
export declare function FormAuthenticationCyberArkVaultSettingToJSON(value?: FormAuthenticationCyberArkVaultSetting | null): any;