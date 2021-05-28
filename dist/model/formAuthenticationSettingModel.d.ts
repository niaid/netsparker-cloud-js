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
import { FormAuthenticationCustomScript } from './formAuthenticationCustomScript';
import { FormAuthenticationPersona } from './formAuthenticationPersona';
import { LogoutKeywordPatternModel } from './logoutKeywordPatternModel';
import { ScanNotificationIntegrationViewModel } from './scanNotificationIntegrationViewModel';
/**
* Represents a model for carrying out form authentication settings.
*/
export declare class FormAuthenticationSettingModel {
    /**
    * Gets or sets the privileged access management integrations.
    */
    'integrations'?: {
        [key: string]: ScanNotificationIntegrationViewModel;
    };
    /**
    * Gets or sets the custom scripts.
    */
    'customScripts'?: Array<FormAuthenticationCustomScript>;
    'interactiveLoginRequired'?: boolean;
    /**
    * Gets or sets the personas validation property.
    */
    'defaultPersonaValidation'?: boolean;
    /**
    * Gets or sets a value indicating whether to detect Bearer token authorization. Default: true
    */
    'detectBearerToken'?: boolean;
    /**
    * Gets or sets whether logout detection is disabled.
    */
    'disableLogoutDetection'?: boolean;
    /**
    * Gets or sets a value indicating whether form authentication is enabled.
    */
    'isEnabled'?: boolean;
    /**
    * Gets or sets the login form URL.
    */
    'loginFormUrl'?: string;
    /**
    * Gets or sets the login required URL.
    */
    'loginRequiredUrl'?: string;
    /**
    * Gets or sets the logout keyword patterns.
    */
    'logoutKeywordPatterns'?: Array<LogoutKeywordPatternModel>;
    /**
    * Gets or sets the JSON serialized logout keyword patterns.
    */
    'logoutKeywordPatternsValue'?: string;
    /**
    * Gets or sets the logout redirect pattern.
    */
    'logoutRedirectPattern'?: string;
    /**
    * Gets or sets a value indicating whether target URL should be overrided with authenticated page.
    */
    'overrideTargetUrl'?: boolean;
    /**
    * Gets or sets the form authentication personas.
    */
    'personas'?: Array<FormAuthenticationPersona>;
    /**
    * Gets or sets the personas validation property.
    */
    'personasValidation'?: boolean;
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