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
import type { FormAuthenticationHashicorpVaultSecretSetting } from './FormAuthenticationHashicorpVaultSecretSetting';
/**
 * Represents HashiCorp authentication setting for agent auth-verifier.
 * @export
 * @interface FormAuthenticationHashicorpVaultSetting
 */
export interface FormAuthenticationHashicorpVaultSetting {
    /**
     * Gets or sets the connection Id.
     * @type {string}
     * @memberof FormAuthenticationHashicorpVaultSetting
     */
    id?: string;
    /**
     *
     * @type {FormAuthenticationHashicorpVaultSecretSetting}
     * @memberof FormAuthenticationHashicorpVaultSetting
     */
    secretSetting?: FormAuthenticationHashicorpVaultSecretSetting;
    /**
     * Gets or sets the token.
     * @type {string}
     * @memberof FormAuthenticationHashicorpVaultSetting
     */
    token?: string;
    /**
     * Gets or sets the URL.
     * @type {string}
     * @memberof FormAuthenticationHashicorpVaultSetting
     */
    url?: string;
    /**
     * Gets or sets the website agent mode.
     * @type {string}
     * @memberof FormAuthenticationHashicorpVaultSetting
     */
    agentMode?: FormAuthenticationHashicorpVaultSettingAgentModeEnum;
    /**
     * Gets or sets the encryption of credentials
     * @type {boolean}
     * @memberof FormAuthenticationHashicorpVaultSetting
     */
    encrypted?: boolean;
    /**
     * Gets or sets the hashicorp auth type.
     * @type {string}
     * @memberof FormAuthenticationHashicorpVaultSetting
     */
    authType?: FormAuthenticationHashicorpVaultSettingAuthTypeEnum;
    /**
     * Gets or sets the certificate for hashicorp tls auth.
     * @type {string}
     * @memberof FormAuthenticationHashicorpVaultSetting
     */
    certificateFileBytes?: string;
    /**
     * Gets or sets the certificate file password for certificate.
     * @type {string}
     * @memberof FormAuthenticationHashicorpVaultSetting
     */
    certificateFilePassword?: string;
    /**
     * Gets or sets the path for certificate.
     * @type {string}
     * @memberof FormAuthenticationHashicorpVaultSetting
     */
    path?: string;
    /**
     * Gets or sets the path for certificate.
     * @type {string}
     * @memberof FormAuthenticationHashicorpVaultSetting
     */
    namespace?: string;
}
/**
 * @export
 */
export declare const FormAuthenticationHashicorpVaultSettingAgentModeEnum: {
    readonly Cloud: "Cloud";
    readonly Internal: "Internal";
};
export type FormAuthenticationHashicorpVaultSettingAgentModeEnum = typeof FormAuthenticationHashicorpVaultSettingAgentModeEnum[keyof typeof FormAuthenticationHashicorpVaultSettingAgentModeEnum];
/**
 * @export
 */
export declare const FormAuthenticationHashicorpVaultSettingAuthTypeEnum: {
    readonly Token: "Token";
    readonly TlsCert: "TLSCert";
};
export type FormAuthenticationHashicorpVaultSettingAuthTypeEnum = typeof FormAuthenticationHashicorpVaultSettingAuthTypeEnum[keyof typeof FormAuthenticationHashicorpVaultSettingAuthTypeEnum];
/**
 * Check if a given object implements the FormAuthenticationHashicorpVaultSetting interface.
 */
export declare function instanceOfFormAuthenticationHashicorpVaultSetting(value: object): boolean;
export declare function FormAuthenticationHashicorpVaultSettingFromJSON(json: any): FormAuthenticationHashicorpVaultSetting;
export declare function FormAuthenticationHashicorpVaultSettingFromJSONTyped(json: any, ignoreDiscriminator: boolean): FormAuthenticationHashicorpVaultSetting;
export declare function FormAuthenticationHashicorpVaultSettingToJSON(value?: FormAuthenticationHashicorpVaultSetting | null): any;
