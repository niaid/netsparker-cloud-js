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

import { mapValues } from '../runtime';
/**
 * Represents a model for carrying out javascript settings.
 * @export
 * @interface JavaScriptSettingsModel
 */
export interface JavaScriptSettingsModel {
    /**
     * Gets or sets the bail threshold.
     * @type {number}
     * @memberof JavaScriptSettingsModel
     */
    bailThreshold?: number;
    /**
     * Gets or sets the confirm open redirect simulate timeout.
     * @type {number}
     * @memberof JavaScriptSettingsModel
     */
    confirmOpenRedirectSimulateTimeout?: number;
    /**
     * Gets or sets the confirm xss simulate timeout.
     * @type {number}
     * @memberof JavaScriptSettingsModel
     */
    confirmXssSimulateTimeout?: number;
    /**
     * Gets or sets a value indicating whether to allow out of scope XML HTTP requests in DOM Parser.
     * @type {boolean}
     * @memberof JavaScriptSettingsModel
     */
    domParserAllowOutOfScopeXmlHttpRequests?: boolean;
    /**
     * Gets or sets a value indicating whether to allow oto block extra navigation on SPAs.
     * @type {boolean}
     * @memberof JavaScriptSettingsModel
     */
    pushStatePrevention?: boolean;
    /**
     * Gets or sets the DOM parser DFS limit.
     * @type {number}
     * @memberof JavaScriptSettingsModel
     */
    domParserDfsLimit?: number;
    /**
     * Gets or sets the DOM parser dotify.
     * @type {boolean}
     * @memberof JavaScriptSettingsModel
     */
    domParserDotify?: boolean;
    /**
     * Gets or sets the DOM parser exclusion CSS selector.
     * @type {string}
     * @memberof JavaScriptSettingsModel
     */
    domParserExclusionCssSelector?: string;
    /**
     * Gets or sets a value indicating whether to extract resources using DOM Parser.
     * @type {boolean}
     * @memberof JavaScriptSettingsModel
     */
    domParserExtractResources?: boolean;
    /**
     * Gets or sets a value indicating whether to filter events that contain a colon in their names.
     * @type {boolean}
     * @memberof JavaScriptSettingsModel
     */
    domParserFilterColonEvents?: boolean;
    /**
     * Gets or sets the DOM parser filter document events.
     * @type {boolean}
     * @memberof JavaScriptSettingsModel
     */
    domParserFilterDocumentEvents?: boolean;
    /**
     * Gets or sets a value indicating whether to ignore document events in DOM Parser.
     * @type {boolean}
     * @memberof JavaScriptSettingsModel
     */
    domParserIgnoreDocumentEvents?: boolean;
    /**
     * Gets or sets the DOM parser load URL timeout.
     * @type {number}
     * @memberof JavaScriptSettingsModel
     */
    domParserLoadUrlTimeout?: number;
    /**
     * Gets or sets the DOM parser maximum option elements per select.
     * @type {number}
     * @memberof JavaScriptSettingsModel
     */
    domParserMaxOptionElementsPerSelect?: number;
    /**
     * Gets or sets the DOM parser persistent javascript cookies.
     * @type {string}
     * @memberof JavaScriptSettingsModel
     */
    domParserPersistentJavaScriptCookies?: string;
    /**
     * Gets or sets the DOM Parser LoadUrl timeout.
     * @type {number}
     * @memberof JavaScriptSettingsModel
     */
    domParserPreSimulateWait?: number;
    /**
     * Gets or sets the DOM parser simulation timeout.
     * @type {number}
     * @memberof JavaScriptSettingsModel
     */
    domParserSimulationTimeout?: number;
    /**
     * Gets or sets a value indicating whether enable DOM parser.
     * @type {boolean}
     * @memberof JavaScriptSettingsModel
     */
    enableDomParser?: boolean;
    /**
     * Gets or sets the interevent timeout.
     * @type {number}
     * @memberof JavaScriptSettingsModel
     */
    intereventTimeout?: number;
    /**
     * Gets or sets the skip element count.
     * @type {number}
     * @memberof JavaScriptSettingsModel
     */
    skipElementCount?: number;
    /**
     * Gets or sets the skip threshold.
     * @type {number}
     * @memberof JavaScriptSettingsModel
     */
    skipThreshold?: number;
    /**
     * Gets or sets the DOM parser exclusion javascript events.
     * @type {string}
     * @memberof JavaScriptSettingsModel
     */
    domParserExclusionJavascriptEvents?: string;
}

/**
 * Check if a given object implements the JavaScriptSettingsModel interface.
 */
export function instanceOfJavaScriptSettingsModel(value: object): boolean {
    return true;
}

export function JavaScriptSettingsModelFromJSON(json: any): JavaScriptSettingsModel {
    return JavaScriptSettingsModelFromJSONTyped(json, false);
}

export function JavaScriptSettingsModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): JavaScriptSettingsModel {
    if (json == null) {
        return json;
    }
    return {
        
        'bailThreshold': json['BailThreshold'] == null ? undefined : json['BailThreshold'],
        'confirmOpenRedirectSimulateTimeout': json['ConfirmOpenRedirectSimulateTimeout'] == null ? undefined : json['ConfirmOpenRedirectSimulateTimeout'],
        'confirmXssSimulateTimeout': json['ConfirmXssSimulateTimeout'] == null ? undefined : json['ConfirmXssSimulateTimeout'],
        'domParserAllowOutOfScopeXmlHttpRequests': json['DomParserAllowOutOfScopeXmlHttpRequests'] == null ? undefined : json['DomParserAllowOutOfScopeXmlHttpRequests'],
        'pushStatePrevention': json['PushStatePrevention'] == null ? undefined : json['PushStatePrevention'],
        'domParserDfsLimit': json['DomParserDfsLimit'] == null ? undefined : json['DomParserDfsLimit'],
        'domParserDotify': json['DomParserDotify'] == null ? undefined : json['DomParserDotify'],
        'domParserExclusionCssSelector': json['DomParserExclusionCssSelector'] == null ? undefined : json['DomParserExclusionCssSelector'],
        'domParserExtractResources': json['DomParserExtractResources'] == null ? undefined : json['DomParserExtractResources'],
        'domParserFilterColonEvents': json['DomParserFilterColonEvents'] == null ? undefined : json['DomParserFilterColonEvents'],
        'domParserFilterDocumentEvents': json['DomParserFilterDocumentEvents'] == null ? undefined : json['DomParserFilterDocumentEvents'],
        'domParserIgnoreDocumentEvents': json['DomParserIgnoreDocumentEvents'] == null ? undefined : json['DomParserIgnoreDocumentEvents'],
        'domParserLoadUrlTimeout': json['DomParserLoadUrlTimeout'] == null ? undefined : json['DomParserLoadUrlTimeout'],
        'domParserMaxOptionElementsPerSelect': json['DomParserMaxOptionElementsPerSelect'] == null ? undefined : json['DomParserMaxOptionElementsPerSelect'],
        'domParserPersistentJavaScriptCookies': json['DomParserPersistentJavaScriptCookies'] == null ? undefined : json['DomParserPersistentJavaScriptCookies'],
        'domParserPreSimulateWait': json['DomParserPreSimulateWait'] == null ? undefined : json['DomParserPreSimulateWait'],
        'domParserSimulationTimeout': json['DomParserSimulationTimeout'] == null ? undefined : json['DomParserSimulationTimeout'],
        'enableDomParser': json['EnableDomParser'] == null ? undefined : json['EnableDomParser'],
        'intereventTimeout': json['IntereventTimeout'] == null ? undefined : json['IntereventTimeout'],
        'skipElementCount': json['SkipElementCount'] == null ? undefined : json['SkipElementCount'],
        'skipThreshold': json['SkipThreshold'] == null ? undefined : json['SkipThreshold'],
        'domParserExclusionJavascriptEvents': json['DomParserExclusionJavascriptEvents'] == null ? undefined : json['DomParserExclusionJavascriptEvents'],
    };
}

export function JavaScriptSettingsModelToJSON(value?: JavaScriptSettingsModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'BailThreshold': value['bailThreshold'],
        'ConfirmOpenRedirectSimulateTimeout': value['confirmOpenRedirectSimulateTimeout'],
        'ConfirmXssSimulateTimeout': value['confirmXssSimulateTimeout'],
        'DomParserAllowOutOfScopeXmlHttpRequests': value['domParserAllowOutOfScopeXmlHttpRequests'],
        'PushStatePrevention': value['pushStatePrevention'],
        'DomParserDfsLimit': value['domParserDfsLimit'],
        'DomParserDotify': value['domParserDotify'],
        'DomParserExclusionCssSelector': value['domParserExclusionCssSelector'],
        'DomParserExtractResources': value['domParserExtractResources'],
        'DomParserFilterColonEvents': value['domParserFilterColonEvents'],
        'DomParserFilterDocumentEvents': value['domParserFilterDocumentEvents'],
        'DomParserIgnoreDocumentEvents': value['domParserIgnoreDocumentEvents'],
        'DomParserLoadUrlTimeout': value['domParserLoadUrlTimeout'],
        'DomParserMaxOptionElementsPerSelect': value['domParserMaxOptionElementsPerSelect'],
        'DomParserPersistentJavaScriptCookies': value['domParserPersistentJavaScriptCookies'],
        'DomParserPreSimulateWait': value['domParserPreSimulateWait'],
        'DomParserSimulationTimeout': value['domParserSimulationTimeout'],
        'EnableDomParser': value['enableDomParser'],
        'IntereventTimeout': value['intereventTimeout'],
        'SkipElementCount': value['skipElementCount'],
        'SkipThreshold': value['skipThreshold'],
        'DomParserExclusionJavascriptEvents': value['domParserExclusionJavascriptEvents'],
    };
}

