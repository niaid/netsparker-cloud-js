"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.CrawlingSettingModel = void 0;
/**
* Represents a model for carrying out crawling settings.
*/
class CrawlingSettingModel {
    static getAttributeTypeMap() {
        return CrawlingSettingModel.attributeTypeMap;
    }
}
exports.CrawlingSettingModel = CrawlingSettingModel;
CrawlingSettingModel.discriminator = undefined;
CrawlingSettingModel.attributeTypeMap = [
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
    }
];
//# sourceMappingURL=crawlingSettingModel.js.map