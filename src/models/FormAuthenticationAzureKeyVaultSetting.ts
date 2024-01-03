/* tslint:disable */
/* eslint-disable */
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

import { exists, mapValues } from '../runtime';
/**
 * FormAuthenticationAzureKeyVaultSetting
 * @export
 * @interface FormAuthenticationAzureKeyVaultSetting
 */
export interface FormAuthenticationAzureKeyVaultSetting {
    /**
     * Gets or sets the integration id.
     * @type {string}
     * @memberof FormAuthenticationAzureKeyVaultSetting
     */
    integrationId?: string;
    /**
     * Gets or sets the username is static or not.
     * @type {boolean}
     * @memberof FormAuthenticationAzureKeyVaultSetting
     */
    useStaticUsername?: boolean;
    /**
     * Gets or sets the static username.
     * @type {string}
     * @memberof FormAuthenticationAzureKeyVaultSetting
     */
    staticUsername?: string;
    /**
     * Gets or sets the username key.
     * @type {string}
     * @memberof FormAuthenticationAzureKeyVaultSetting
     */
    usernameKey?: string;
    /**
     * Gets or sets the password key.
     * @type {string}
     * @memberof FormAuthenticationAzureKeyVaultSetting
     */
    passwordKey?: string;
    /**
     * Gets or sets the clientId.
     * @type {string}
     * @memberof FormAuthenticationAzureKeyVaultSetting
     */
    clientID?: string;
    /**
     * Gets or sets the secret.
     * @type {string}
     * @memberof FormAuthenticationAzureKeyVaultSetting
     */
    clientSecret?: string;
    /**
     * Gets or sets the TenantId.
     * @type {string}
     * @memberof FormAuthenticationAzureKeyVaultSetting
     */
    tenantId?: string;
    /**
     * Gets or sets the Vault Name.
     * @type {string}
     * @memberof FormAuthenticationAzureKeyVaultSetting
     */
    vaultName?: string;
    /**
     * Gets or sets website agent mode.
     * @type {string}
     * @memberof FormAuthenticationAzureKeyVaultSetting
     */
    agentMode?: FormAuthenticationAzureKeyVaultSettingAgentModeEnum;
}

/**
* @export
* @enum {string}
*/
export enum FormAuthenticationAzureKeyVaultSettingAgentModeEnum {
    Cloud = 'Cloud',
    Internal = 'Internal'
}


/**
 * Check if a given object implements the FormAuthenticationAzureKeyVaultSetting interface.
 */
export function instanceOfFormAuthenticationAzureKeyVaultSetting(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function FormAuthenticationAzureKeyVaultSettingFromJSON(json: any): FormAuthenticationAzureKeyVaultSetting {
    return FormAuthenticationAzureKeyVaultSettingFromJSONTyped(json, false);
}

export function FormAuthenticationAzureKeyVaultSettingFromJSONTyped(json: any, ignoreDiscriminator: boolean): FormAuthenticationAzureKeyVaultSetting {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'integrationId': !exists(json, 'IntegrationId') ? undefined : json['IntegrationId'],
        'useStaticUsername': !exists(json, 'UseStaticUsername') ? undefined : json['UseStaticUsername'],
        'staticUsername': !exists(json, 'StaticUsername') ? undefined : json['StaticUsername'],
        'usernameKey': !exists(json, 'UsernameKey') ? undefined : json['UsernameKey'],
        'passwordKey': !exists(json, 'PasswordKey') ? undefined : json['PasswordKey'],
        'clientID': !exists(json, 'ClientID') ? undefined : json['ClientID'],
        'clientSecret': !exists(json, 'ClientSecret') ? undefined : json['ClientSecret'],
        'tenantId': !exists(json, 'TenantId') ? undefined : json['TenantId'],
        'vaultName': !exists(json, 'VaultName') ? undefined : json['VaultName'],
        'agentMode': !exists(json, 'AgentMode') ? undefined : json['AgentMode'],
    };
}

export function FormAuthenticationAzureKeyVaultSettingToJSON(value?: FormAuthenticationAzureKeyVaultSetting | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'IntegrationId': value.integrationId,
        'UseStaticUsername': value.useStaticUsername,
        'StaticUsername': value.staticUsername,
        'UsernameKey': value.usernameKey,
        'PasswordKey': value.passwordKey,
        'ClientID': value.clientID,
        'ClientSecret': value.clientSecret,
        'TenantId': value.tenantId,
        'VaultName': value.vaultName,
        'AgentMode': value.agentMode,
    };
}

