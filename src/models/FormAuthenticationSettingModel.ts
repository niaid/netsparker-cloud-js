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
import type { AuthorizationTokenRule } from './AuthorizationTokenRule';
import {
    AuthorizationTokenRuleFromJSON,
    AuthorizationTokenRuleFromJSONTyped,
    AuthorizationTokenRuleToJSON,
} from './AuthorizationTokenRule';
import type { FormAuthenticationCustomScript } from './FormAuthenticationCustomScript';
import {
    FormAuthenticationCustomScriptFromJSON,
    FormAuthenticationCustomScriptFromJSONTyped,
    FormAuthenticationCustomScriptToJSON,
} from './FormAuthenticationCustomScript';
import type { FormAuthenticationPersona } from './FormAuthenticationPersona';
import {
    FormAuthenticationPersonaFromJSON,
    FormAuthenticationPersonaFromJSONTyped,
    FormAuthenticationPersonaToJSON,
} from './FormAuthenticationPersona';
import type { LogoutKeywordPatternModel } from './LogoutKeywordPatternModel';
import {
    LogoutKeywordPatternModelFromJSON,
    LogoutKeywordPatternModelFromJSONTyped,
    LogoutKeywordPatternModelToJSON,
} from './LogoutKeywordPatternModel';
import type { ScanNotificationIntegrationViewModel } from './ScanNotificationIntegrationViewModel';
import {
    ScanNotificationIntegrationViewModelFromJSON,
    ScanNotificationIntegrationViewModelFromJSONTyped,
    ScanNotificationIntegrationViewModelToJSON,
} from './ScanNotificationIntegrationViewModel';

/**
 * Represents a model for carrying out form authentication settings.
 * @export
 * @interface FormAuthenticationSettingModel
 */
export interface FormAuthenticationSettingModel {
    /**
     * Gets or sets the Secrets and Encryption Management integrations.
     * @type {{ [key: string]: ScanNotificationIntegrationViewModel; }}
     * @memberof FormAuthenticationSettingModel
     */
    integrations?: { [key: string]: ScanNotificationIntegrationViewModel; };
    /**
     * Gets or sets the custom scripts.
     * @type {Array<FormAuthenticationCustomScript>}
     * @memberof FormAuthenticationSettingModel
     */
    customScripts?: Array<FormAuthenticationCustomScript>;
    /**
     * 
     * @type {boolean}
     * @memberof FormAuthenticationSettingModel
     */
    interactiveLoginRequired?: boolean;
    /**
     * Gets or sets the personas validation property.
     * @type {boolean}
     * @memberof FormAuthenticationSettingModel
     */
    readonly defaultPersonaValidation?: boolean;
    /**
     * Gets or sets a value indicating whether to detect Bearer token authorization. Default: true
     * @type {boolean}
     * @memberof FormAuthenticationSettingModel
     */
    detectBearerToken?: boolean;
    /**
     * Gets or sets whether logout detection is disabled.
     * @type {boolean}
     * @memberof FormAuthenticationSettingModel
     */
    disableLogoutDetection?: boolean;
    /**
     * Gets or sets a value indicating whether form authentication is enabled.
     * @type {boolean}
     * @memberof FormAuthenticationSettingModel
     */
    isEnabled?: boolean;
    /**
     * Gets a value indicating whether form authantication is not verified
     * @type {boolean}
     * @memberof FormAuthenticationSettingModel
     */
    readonly isNotVerified?: boolean;
    /**
     * Gets or sets the login form URL.
     * @type {string}
     * @memberof FormAuthenticationSettingModel
     */
    loginFormUrl?: string;
    /**
     * Gets or sets the login required URL.
     * @type {string}
     * @memberof FormAuthenticationSettingModel
     */
    loginRequiredUrl?: string;
    /**
     * Gets or sets the logout keyword patterns.
     * @type {Array<LogoutKeywordPatternModel>}
     * @memberof FormAuthenticationSettingModel
     */
    logoutKeywordPatterns?: Array<LogoutKeywordPatternModel>;
    /**
     * Gets or sets the JSON serialized logout keyword patterns.
     * @type {string}
     * @memberof FormAuthenticationSettingModel
     */
    logoutKeywordPatternsValue?: string;
    /**
     * Gets or sets the logout redirect pattern.
     * @type {string}
     * @memberof FormAuthenticationSettingModel
     */
    logoutRedirectPattern?: string;
    /**
     * Gets or sets a value indicating whether target URL should be overrided with authenticated page.
     * @type {boolean}
     * @memberof FormAuthenticationSettingModel
     */
    overrideTargetUrl?: boolean;
    /**
     * Gets or sets the form authentication personas.
     * @type {Array<FormAuthenticationPersona>}
     * @memberof FormAuthenticationSettingModel
     */
    personas?: Array<FormAuthenticationPersona>;
    /**
     * Gets or sets the personas validation property.
     * @type {boolean}
     * @memberof FormAuthenticationSettingModel
     */
    readonly personasValidation?: boolean;
    /**
     * Gets or sets the token mappers.
     * @type {Array<AuthorizationTokenRule>}
     * @memberof FormAuthenticationSettingModel
     */
    authorizationTokenRules?: Array<AuthorizationTokenRule>;
}

/**
 * Check if a given object implements the FormAuthenticationSettingModel interface.
 */
export function instanceOfFormAuthenticationSettingModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function FormAuthenticationSettingModelFromJSON(json: any): FormAuthenticationSettingModel {
    return FormAuthenticationSettingModelFromJSONTyped(json, false);
}

export function FormAuthenticationSettingModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): FormAuthenticationSettingModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'integrations': !exists(json, 'Integrations') ? undefined : (mapValues(json['Integrations'], ScanNotificationIntegrationViewModelFromJSON)),
        'customScripts': !exists(json, 'CustomScripts') ? undefined : ((json['CustomScripts'] as Array<any>).map(FormAuthenticationCustomScriptFromJSON)),
        'interactiveLoginRequired': !exists(json, 'InteractiveLoginRequired') ? undefined : json['InteractiveLoginRequired'],
        'defaultPersonaValidation': !exists(json, 'DefaultPersonaValidation') ? undefined : json['DefaultPersonaValidation'],
        'detectBearerToken': !exists(json, 'DetectBearerToken') ? undefined : json['DetectBearerToken'],
        'disableLogoutDetection': !exists(json, 'DisableLogoutDetection') ? undefined : json['DisableLogoutDetection'],
        'isEnabled': !exists(json, 'IsEnabled') ? undefined : json['IsEnabled'],
        'isNotVerified': !exists(json, 'IsNotVerified') ? undefined : json['IsNotVerified'],
        'loginFormUrl': !exists(json, 'LoginFormUrl') ? undefined : json['LoginFormUrl'],
        'loginRequiredUrl': !exists(json, 'LoginRequiredUrl') ? undefined : json['LoginRequiredUrl'],
        'logoutKeywordPatterns': !exists(json, 'LogoutKeywordPatterns') ? undefined : ((json['LogoutKeywordPatterns'] as Array<any>).map(LogoutKeywordPatternModelFromJSON)),
        'logoutKeywordPatternsValue': !exists(json, 'LogoutKeywordPatternsValue') ? undefined : json['LogoutKeywordPatternsValue'],
        'logoutRedirectPattern': !exists(json, 'LogoutRedirectPattern') ? undefined : json['LogoutRedirectPattern'],
        'overrideTargetUrl': !exists(json, 'OverrideTargetUrl') ? undefined : json['OverrideTargetUrl'],
        'personas': !exists(json, 'Personas') ? undefined : ((json['Personas'] as Array<any>).map(FormAuthenticationPersonaFromJSON)),
        'personasValidation': !exists(json, 'PersonasValidation') ? undefined : json['PersonasValidation'],
        'authorizationTokenRules': !exists(json, 'AuthorizationTokenRules') ? undefined : ((json['AuthorizationTokenRules'] as Array<any>).map(AuthorizationTokenRuleFromJSON)),
    };
}

export function FormAuthenticationSettingModelToJSON(value?: FormAuthenticationSettingModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Integrations': value.integrations === undefined ? undefined : (mapValues(value.integrations, ScanNotificationIntegrationViewModelToJSON)),
        'CustomScripts': value.customScripts === undefined ? undefined : ((value.customScripts as Array<any>).map(FormAuthenticationCustomScriptToJSON)),
        'InteractiveLoginRequired': value.interactiveLoginRequired,
        'DetectBearerToken': value.detectBearerToken,
        'DisableLogoutDetection': value.disableLogoutDetection,
        'IsEnabled': value.isEnabled,
        'LoginFormUrl': value.loginFormUrl,
        'LoginRequiredUrl': value.loginRequiredUrl,
        'LogoutKeywordPatterns': value.logoutKeywordPatterns === undefined ? undefined : ((value.logoutKeywordPatterns as Array<any>).map(LogoutKeywordPatternModelToJSON)),
        'LogoutKeywordPatternsValue': value.logoutKeywordPatternsValue,
        'LogoutRedirectPattern': value.logoutRedirectPattern,
        'OverrideTargetUrl': value.overrideTargetUrl,
        'Personas': value.personas === undefined ? undefined : ((value.personas as Array<any>).map(FormAuthenticationPersonaToJSON)),
        'AuthorizationTokenRules': value.authorizationTokenRules === undefined ? undefined : ((value.authorizationTokenRules as Array<any>).map(AuthorizationTokenRuleToJSON)),
    };
}

