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
 * Represents a model for carrying out crawling settings.
 * @export
 * @interface CrawlingSettingModel
 */
export interface CrawlingSettingModel {
    /**
     * Gets or sets a value indicating whether parameter based navigation is enabled.
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    enableParameterBasedNavigation?: boolean;
    /**
     * Gets or sets whether REST Web Service parser is enabled.
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    enableRestWebServiceParser?: boolean;
    /**
     * Gets or sets whether SOAP Web Service parser is enabled.
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    enableSoapWebServiceParser?: boolean;
    /**
     * Gets or sets a value indicating whether text parser is enabled.
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    enableTextParser?: boolean;
    /**
     * Gets or sets a value indicating whether "fallback to get" is enabled
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    fallbackToGet?: boolean;
    /**
     * Gets or sets a value indicating whether "fallback to get" is enabled
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    enableFragmentParsing?: boolean;
    /**
     * Gets or sets the file extensions that will be used in File Extensions RegEx.
     * @type {string}
     * @memberof CrawlingSettingModel
     */
    fileExtensions?: string;
    /**
     * Gets or sets the maximum crawler URL count.
     * @type {number}
     * @memberof CrawlingSettingModel
     */
    maximumCrawlerUrlCount?: number;
    /**
     * Gets or sets the maximum signature.
     * @type {number}
     * @memberof CrawlingSettingModel
     */
    maximumSignature?: number;
    /**
     * Gets or sets the page visit limit for links containing navigation parameter.
     * @type {number}
     * @memberof CrawlingSettingModel
     */
    navigationParameterPageVisitLimit?: number;
    /**
     * Gets or sets the regular expression pattern for navigation parameter.
     * @type {string}
     * @memberof CrawlingSettingModel
     */
    navigationParameterRegexPattern?: string;
    /**
     * Gets or sets the page visit limit.
     * @type {number}
     * @memberof CrawlingSettingModel
     */
    pageVisitLimit?: number;
    /**
     * Gets or sets the page visit limit.
     * @type {number}
     * @memberof CrawlingSettingModel
     */
    maximumUrlRewriteSignature?: number;
    /**
     * Gets or sets a value indicating whether the crawler should wait resource finder.
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    waitResourceFinder?: boolean;
    /**
     * Specifies whether all related links should be crawled when a new link is found.
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    addRelatedLinks?: boolean;
    /**
     * If enabled, only query string parameters will be recognized as navigation parameters.
     * @type {boolean}
     * @memberof CrawlingSettingModel
     */
    enableQueryBasedParameterBasedNavigation?: boolean;
}

/**
 * Check if a given object implements the CrawlingSettingModel interface.
 */
export function instanceOfCrawlingSettingModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function CrawlingSettingModelFromJSON(json: any): CrawlingSettingModel {
    return CrawlingSettingModelFromJSONTyped(json, false);
}

export function CrawlingSettingModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): CrawlingSettingModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'enableParameterBasedNavigation': !exists(json, 'EnableParameterBasedNavigation') ? undefined : json['EnableParameterBasedNavigation'],
        'enableRestWebServiceParser': !exists(json, 'EnableRestWebServiceParser') ? undefined : json['EnableRestWebServiceParser'],
        'enableSoapWebServiceParser': !exists(json, 'EnableSoapWebServiceParser') ? undefined : json['EnableSoapWebServiceParser'],
        'enableTextParser': !exists(json, 'EnableTextParser') ? undefined : json['EnableTextParser'],
        'fallbackToGet': !exists(json, 'FallbackToGet') ? undefined : json['FallbackToGet'],
        'enableFragmentParsing': !exists(json, 'EnableFragmentParsing') ? undefined : json['EnableFragmentParsing'],
        'fileExtensions': !exists(json, 'FileExtensions') ? undefined : json['FileExtensions'],
        'maximumCrawlerUrlCount': !exists(json, 'MaximumCrawlerUrlCount') ? undefined : json['MaximumCrawlerUrlCount'],
        'maximumSignature': !exists(json, 'MaximumSignature') ? undefined : json['MaximumSignature'],
        'navigationParameterPageVisitLimit': !exists(json, 'NavigationParameterPageVisitLimit') ? undefined : json['NavigationParameterPageVisitLimit'],
        'navigationParameterRegexPattern': !exists(json, 'NavigationParameterRegexPattern') ? undefined : json['NavigationParameterRegexPattern'],
        'pageVisitLimit': !exists(json, 'PageVisitLimit') ? undefined : json['PageVisitLimit'],
        'maximumUrlRewriteSignature': !exists(json, 'MaximumUrlRewriteSignature') ? undefined : json['MaximumUrlRewriteSignature'],
        'waitResourceFinder': !exists(json, 'WaitResourceFinder') ? undefined : json['WaitResourceFinder'],
        'addRelatedLinks': !exists(json, 'AddRelatedLinks') ? undefined : json['AddRelatedLinks'],
        'enableQueryBasedParameterBasedNavigation': !exists(json, 'EnableQueryBasedParameterBasedNavigation') ? undefined : json['EnableQueryBasedParameterBasedNavigation'],
    };
}

export function CrawlingSettingModelToJSON(value?: CrawlingSettingModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'EnableParameterBasedNavigation': value.enableParameterBasedNavigation,
        'EnableRestWebServiceParser': value.enableRestWebServiceParser,
        'EnableSoapWebServiceParser': value.enableSoapWebServiceParser,
        'EnableTextParser': value.enableTextParser,
        'FallbackToGet': value.fallbackToGet,
        'EnableFragmentParsing': value.enableFragmentParsing,
        'FileExtensions': value.fileExtensions,
        'MaximumCrawlerUrlCount': value.maximumCrawlerUrlCount,
        'MaximumSignature': value.maximumSignature,
        'NavigationParameterPageVisitLimit': value.navigationParameterPageVisitLimit,
        'NavigationParameterRegexPattern': value.navigationParameterRegexPattern,
        'PageVisitLimit': value.pageVisitLimit,
        'MaximumUrlRewriteSignature': value.maximumUrlRewriteSignature,
        'WaitResourceFinder': value.waitResourceFinder,
        'AddRelatedLinks': value.addRelatedLinks,
        'EnableQueryBasedParameterBasedNavigation': value.enableQueryBasedParameterBasedNavigation,
    };
}

