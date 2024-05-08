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
import type { FormAuthenticationPersona } from './FormAuthenticationPersona';
import type { LogoutKeywordPatternModel } from './LogoutKeywordPatternModel';
import type { FormAuthenticationCustomScript } from './FormAuthenticationCustomScript';
import type { ScanNotificationIntegrationViewModel } from './ScanNotificationIntegrationViewModel';
import type { AuthorizationTokenRule } from './AuthorizationTokenRule';
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
    integrations?: {
        [key: string]: ScanNotificationIntegrationViewModel;
    };
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
     * Gets or sets a value indicating whether to diagnostics logging enabled.
     * @type {boolean}
     * @memberof FormAuthenticationSettingModel
     */
    enableDiagnosticsLogging?: boolean;
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
export declare function instanceOfFormAuthenticationSettingModel(value: object): boolean;
export declare function FormAuthenticationSettingModelFromJSON(json: any): FormAuthenticationSettingModel;
export declare function FormAuthenticationSettingModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): FormAuthenticationSettingModel;
export declare function FormAuthenticationSettingModelToJSON(value?: Omit<FormAuthenticationSettingModel, 'DefaultPersonaValidation' | 'IsNotVerified' | 'PersonasValidation'> | null): any;
