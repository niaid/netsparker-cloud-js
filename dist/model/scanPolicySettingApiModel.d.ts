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
import { AttackingSettingModel } from './attackingSettingModel';
import { AutoCompleteSettingModel } from './autoCompleteSettingModel';
import { BruteForceSettingModel } from './bruteForceSettingModel';
import { CrawlingSettingModel } from './crawlingSettingModel';
import { CsrfSettingModel } from './csrfSettingModel';
import { Custom404SettingModel } from './custom404SettingModel';
import { CustomHttpHeaderSetting } from './customHttpHeaderSetting';
import { EmailPatternSetting } from './emailPatternSetting';
import { ExtensionSettingModel } from './extensionSettingModel';
import { FormValueSettingModel } from './formValueSettingModel';
import { HttpRequestSettingModel } from './httpRequestSettingModel';
import { IgnorePatternSettingModel } from './ignorePatternSettingModel';
import { JavaScriptSettingsModel } from './javaScriptSettingsModel';
import { ProxySettingsModel } from './proxySettingsModel';
import { ScopeSettingModel } from './scopeSettingModel';
import { SecurityCheckGroupParentModel } from './securityCheckGroupParentModel';
import { SensitiveKeywordSettingModel } from './sensitiveKeywordSettingModel';
import { SslTlsSettingModel } from './sslTlsSettingModel';
import { WebStorageSetting } from './webStorageSetting';
/**
* Represents a model for carrying out scan policy settings.
*/
export declare class ScanPolicySettingApiModel {
    /**
    * Gets or sets the identifier.
    */
    'id'?: string;
    /**
    * Gets or sets a value indicating whether this scan policy is shared.
    */
    'isShared'?: boolean;
    /**
    * Gets the desktop identifier.
    */
    'desktopId'?: string;
    'attackingSettings': AttackingSettingModel;
    /**
    * Gets or sets the auto complete settings.
    */
    'autoCompleteSettings'?: Array<AutoCompleteSettingModel>;
    'bruteForceSettings': BruteForceSettingModel;
    'crawlingSettings': CrawlingSettingModel;
    'csrfSettings'?: CsrfSettingModel;
    'custom404Settings': Custom404SettingModel;
    /**
    * Gets or sets the custom HTTP header settings.
    */
    'customHttpHeaderSettings'?: Array<CustomHttpHeaderSetting>;
    /**
    * Gets or sets the description.
    */
    'description'?: string;
    /**
    * Gets or sets a value indicating whether knowledgebase is enabled.
    */
    'enableKnowledgebase'?: boolean;
    /**
    * Gets or sets the form value settings.
    */
    'formValueSettings'?: Array<FormValueSettingModel>;
    'httpRequestSettings': HttpRequestSettingModel;
    /**
    * Gets or sets the ignored email patterns.
    */
    'ignoredEmailPatterns'?: Array<EmailPatternSetting>;
    /**
    * Gets or sets the ignored parameter patterns.
    */
    'ignorePatternSettings'?: Array<IgnorePatternSettingModel>;
    'javaScriptSettings': JavaScriptSettingsModel;
    /**
    * Gets or sets the name.
    */
    'name': string;
    'proxySettings'?: ProxySettingsModel;
    'scopeSettings': ScopeSettingModel;
    /**
    * Gets or sets the engine settings.
    */
    'securityCheckGroupParents'?: Array<SecurityCheckGroupParentModel>;
    /**
    * Gets or sets the selected website groups.
    */
    'selectedGroups'?: Array<string>;
    /**
    * Gets or sets the sensitive keyword settings.
    */
    'sensitiveKeywordSettings'?: Array<SensitiveKeywordSettingModel>;
    'sslTlsSettingModel': SslTlsSettingModel;
    /**
    * Gets or sets the Web Storage Settings
    */
    'webStorageSettings'?: Array<WebStorageSetting>;
    /**
    * Gets or sets the Extension Settings
    */
    'extensionSettings'?: Array<ExtensionSettingModel>;
    /**
    * Gets or sets the resource finders.
    */
    'resourceFinders'?: Array<string>;
    /**
    * Gets or sets the cloned scan polic setting identifier.
    */
    'clonedScanPolicySettingId'?: string;
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
