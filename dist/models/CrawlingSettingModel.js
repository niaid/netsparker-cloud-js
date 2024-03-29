"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.CrawlingSettingModelToJSON = exports.CrawlingSettingModelFromJSONTyped = exports.CrawlingSettingModelFromJSON = exports.instanceOfCrawlingSettingModel = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the CrawlingSettingModel interface.
 */
function instanceOfCrawlingSettingModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfCrawlingSettingModel = instanceOfCrawlingSettingModel;
function CrawlingSettingModelFromJSON(json) {
    return CrawlingSettingModelFromJSONTyped(json, false);
}
exports.CrawlingSettingModelFromJSON = CrawlingSettingModelFromJSON;
function CrawlingSettingModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'enableParameterBasedNavigation': !(0, runtime_1.exists)(json, 'EnableParameterBasedNavigation') ? undefined : json['EnableParameterBasedNavigation'],
        'enableRestWebServiceParser': !(0, runtime_1.exists)(json, 'EnableRestWebServiceParser') ? undefined : json['EnableRestWebServiceParser'],
        'enableSoapWebServiceParser': !(0, runtime_1.exists)(json, 'EnableSoapWebServiceParser') ? undefined : json['EnableSoapWebServiceParser'],
        'enableTextParser': !(0, runtime_1.exists)(json, 'EnableTextParser') ? undefined : json['EnableTextParser'],
        'fallbackToGet': !(0, runtime_1.exists)(json, 'FallbackToGet') ? undefined : json['FallbackToGet'],
        'enableFragmentParsing': !(0, runtime_1.exists)(json, 'EnableFragmentParsing') ? undefined : json['EnableFragmentParsing'],
        'fileExtensions': !(0, runtime_1.exists)(json, 'FileExtensions') ? undefined : json['FileExtensions'],
        'maximumCrawlerUrlCount': !(0, runtime_1.exists)(json, 'MaximumCrawlerUrlCount') ? undefined : json['MaximumCrawlerUrlCount'],
        'maximumSignature': !(0, runtime_1.exists)(json, 'MaximumSignature') ? undefined : json['MaximumSignature'],
        'navigationParameterPageVisitLimit': !(0, runtime_1.exists)(json, 'NavigationParameterPageVisitLimit') ? undefined : json['NavigationParameterPageVisitLimit'],
        'navigationParameterRegexPattern': !(0, runtime_1.exists)(json, 'NavigationParameterRegexPattern') ? undefined : json['NavigationParameterRegexPattern'],
        'pageVisitLimit': !(0, runtime_1.exists)(json, 'PageVisitLimit') ? undefined : json['PageVisitLimit'],
        'maximumUrlRewriteSignature': !(0, runtime_1.exists)(json, 'MaximumUrlRewriteSignature') ? undefined : json['MaximumUrlRewriteSignature'],
        'waitResourceFinder': !(0, runtime_1.exists)(json, 'WaitResourceFinder') ? undefined : json['WaitResourceFinder'],
        'addRelatedLinks': !(0, runtime_1.exists)(json, 'AddRelatedLinks') ? undefined : json['AddRelatedLinks'],
        'enableQueryBasedParameterBasedNavigation': !(0, runtime_1.exists)(json, 'EnableQueryBasedParameterBasedNavigation') ? undefined : json['EnableQueryBasedParameterBasedNavigation'],
    };
}
exports.CrawlingSettingModelFromJSONTyped = CrawlingSettingModelFromJSONTyped;
function CrawlingSettingModelToJSON(value) {
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
exports.CrawlingSettingModelToJSON = CrawlingSettingModelToJSON;
//# sourceMappingURL=CrawlingSettingModel.js.map