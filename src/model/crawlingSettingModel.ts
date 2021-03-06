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

import { RequestFile } from './models';

/**
* Represents a model for carrying out crawling settings.
*/
export class CrawlingSettingModel {
    /**
    * Gets or sets a value indicating whether parameter based navigation is enabled.
    */
    'enableParameterBasedNavigation'?: boolean;
    /**
    * Gets or sets whether REST Web Service parser is enabled.
    */
    'enableRestWebServiceParser'?: boolean;
    /**
    * Gets or sets whether SOAP Web Service parser is enabled.
    */
    'enableSoapWebServiceParser'?: boolean;
    /**
    * Gets or sets a value indicating whether text parser is enabled.
    */
    'enableTextParser'?: boolean;
    /**
    * Gets or sets a value indicating whether \"fallback to get\" is enabled
    */
    'fallbackToGet'?: boolean;
    /**
    * Gets or sets a value indicating whether \"fallback to get\" is enabled
    */
    'enableFragmentParsing'?: boolean;
    /**
    * Gets or sets the file extensions that will be used in File Extensions RegEx.
    */
    'fileExtensions'?: string;
    /**
    * Gets or sets the maximum crawler URL count.
    */
    'maximumCrawlerUrlCount'?: number;
    /**
    * Gets or sets the maximum signature.
    */
    'maximumSignature'?: number;
    /**
    * Gets or sets the page visit limit for links containing navigation parameter.
    */
    'navigationParameterPageVisitLimit'?: number;
    /**
    * Gets or sets the regular expression pattern for navigation parameter.
    */
    'navigationParameterRegexPattern'?: string;
    /**
    * Gets or sets the page visit limit.
    */
    'pageVisitLimit'?: number;
    /**
    * Gets or sets the page visit limit.
    */
    'maximumUrlRewriteSignature'?: number;
    /**
    * Gets or sets a value indicating whether the crawler should wait resource finder.
    */
    'waitResourceFinder'?: boolean;
    /**
    * Specifies whether all related links should be crawled when a new link is found.
    */
    'addRelatedLinks'?: boolean;
    /**
    * If enabled, only query string parameters will be recognized as navigation parameters.
    */
    'enableQueryBasedParameterBasedNavigation'?: boolean;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "enableParameterBasedNavigation",
            "baseName": "EnableParameterBasedNavigation",
            "type": "boolean"
        },
        {
            "name": "enableRestWebServiceParser",
            "baseName": "EnableRestWebServiceParser",
            "type": "boolean"
        },
        {
            "name": "enableSoapWebServiceParser",
            "baseName": "EnableSoapWebServiceParser",
            "type": "boolean"
        },
        {
            "name": "enableTextParser",
            "baseName": "EnableTextParser",
            "type": "boolean"
        },
        {
            "name": "fallbackToGet",
            "baseName": "FallbackToGet",
            "type": "boolean"
        },
        {
            "name": "enableFragmentParsing",
            "baseName": "EnableFragmentParsing",
            "type": "boolean"
        },
        {
            "name": "fileExtensions",
            "baseName": "FileExtensions",
            "type": "string"
        },
        {
            "name": "maximumCrawlerUrlCount",
            "baseName": "MaximumCrawlerUrlCount",
            "type": "number"
        },
        {
            "name": "maximumSignature",
            "baseName": "MaximumSignature",
            "type": "number"
        },
        {
            "name": "navigationParameterPageVisitLimit",
            "baseName": "NavigationParameterPageVisitLimit",
            "type": "number"
        },
        {
            "name": "navigationParameterRegexPattern",
            "baseName": "NavigationParameterRegexPattern",
            "type": "string"
        },
        {
            "name": "pageVisitLimit",
            "baseName": "PageVisitLimit",
            "type": "number"
        },
        {
            "name": "maximumUrlRewriteSignature",
            "baseName": "MaximumUrlRewriteSignature",
            "type": "number"
        },
        {
            "name": "waitResourceFinder",
            "baseName": "WaitResourceFinder",
            "type": "boolean"
        },
        {
            "name": "addRelatedLinks",
            "baseName": "AddRelatedLinks",
            "type": "boolean"
        },
        {
            "name": "enableQueryBasedParameterBasedNavigation",
            "baseName": "EnableQueryBasedParameterBasedNavigation",
            "type": "boolean"
        }    ];

    static getAttributeTypeMap() {
        return CrawlingSettingModel.attributeTypeMap;
    }
}

