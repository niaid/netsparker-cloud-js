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
exports.UrlRewriteSettingToJSON = exports.UrlRewriteSettingFromJSONTyped = exports.UrlRewriteSettingFromJSON = exports.instanceOfUrlRewriteSetting = exports.UrlRewriteSettingUrlRewriteModeEnum = void 0;
const runtime_1 = require("../runtime");
const UrlRewriteExcludedPathModel_1 = require("./UrlRewriteExcludedPathModel");
const UrlRewriteRuleModel_1 = require("./UrlRewriteRuleModel");
/**
* @export
* @enum {string}
*/
var UrlRewriteSettingUrlRewriteModeEnum;
(function (UrlRewriteSettingUrlRewriteModeEnum) {
    UrlRewriteSettingUrlRewriteModeEnum["None"] = "None";
    UrlRewriteSettingUrlRewriteModeEnum["Heuristic"] = "Heuristic";
    UrlRewriteSettingUrlRewriteModeEnum["Custom"] = "Custom";
})(UrlRewriteSettingUrlRewriteModeEnum = exports.UrlRewriteSettingUrlRewriteModeEnum || (exports.UrlRewriteSettingUrlRewriteModeEnum = {}));
/**
 * Check if a given object implements the UrlRewriteSetting interface.
 */
function instanceOfUrlRewriteSetting(value) {
    let isInstance = true;
    isInstance = isInstance && "maxDynamicSignatures" in value;
    isInstance = isInstance && "subPathMaxDynamicSignatures" in value;
    isInstance = isInstance && "urlRewriteBlockSeparators" in value;
    return isInstance;
}
exports.instanceOfUrlRewriteSetting = instanceOfUrlRewriteSetting;
function UrlRewriteSettingFromJSON(json) {
    return UrlRewriteSettingFromJSONTyped(json, false);
}
exports.UrlRewriteSettingFromJSON = UrlRewriteSettingFromJSON;
function UrlRewriteSettingFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'enableHeuristicChecksInCustomUrlRewrite': !(0, runtime_1.exists)(json, 'EnableHeuristicChecksInCustomUrlRewrite') ? undefined : json['EnableHeuristicChecksInCustomUrlRewrite'],
        'maxDynamicSignatures': json['MaxDynamicSignatures'],
        'subPathMaxDynamicSignatures': json['SubPathMaxDynamicSignatures'],
        'urlRewriteAnalyzableExtensions': !(0, runtime_1.exists)(json, 'UrlRewriteAnalyzableExtensions') ? undefined : json['UrlRewriteAnalyzableExtensions'],
        'urlRewriteBlockSeparators': json['UrlRewriteBlockSeparators'],
        'urlRewriteMode': !(0, runtime_1.exists)(json, 'UrlRewriteMode') ? undefined : json['UrlRewriteMode'],
        'urlRewriteRules': !(0, runtime_1.exists)(json, 'UrlRewriteRules') ? undefined : (json['UrlRewriteRules'].map(UrlRewriteRuleModel_1.UrlRewriteRuleModelFromJSON)),
        'urlRewriteExcludedLinks': !(0, runtime_1.exists)(json, 'UrlRewriteExcludedLinks') ? undefined : (json['UrlRewriteExcludedLinks'].map(UrlRewriteExcludedPathModel_1.UrlRewriteExcludedPathModelFromJSON)),
    };
}
exports.UrlRewriteSettingFromJSONTyped = UrlRewriteSettingFromJSONTyped;
function UrlRewriteSettingToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'EnableHeuristicChecksInCustomUrlRewrite': value.enableHeuristicChecksInCustomUrlRewrite,
        'MaxDynamicSignatures': value.maxDynamicSignatures,
        'SubPathMaxDynamicSignatures': value.subPathMaxDynamicSignatures,
        'UrlRewriteAnalyzableExtensions': value.urlRewriteAnalyzableExtensions,
        'UrlRewriteBlockSeparators': value.urlRewriteBlockSeparators,
        'UrlRewriteMode': value.urlRewriteMode,
        'UrlRewriteRules': value.urlRewriteRules === undefined ? undefined : (value.urlRewriteRules.map(UrlRewriteRuleModel_1.UrlRewriteRuleModelToJSON)),
        'UrlRewriteExcludedLinks': value.urlRewriteExcludedLinks === undefined ? undefined : (value.urlRewriteExcludedLinks.map(UrlRewriteExcludedPathModel_1.UrlRewriteExcludedPathModelToJSON)),
    };
}
exports.UrlRewriteSettingToJSON = UrlRewriteSettingToJSON;
//# sourceMappingURL=UrlRewriteSetting.js.map