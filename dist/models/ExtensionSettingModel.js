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
exports.ExtensionSettingModelToJSON = exports.ExtensionSettingModelFromJSONTyped = exports.ExtensionSettingModelFromJSON = exports.instanceOfExtensionSettingModel = exports.ExtensionSettingModelCrawlOptionEnum = exports.ExtensionSettingModelAttackOptionEnum = void 0;
/**
 * @export
 */
exports.ExtensionSettingModelAttackOptionEnum = {
    DoNotAttack: 'DoNotAttack',
    AttackParameters: 'AttackParameters',
    AttackParametersAndQueryString: 'AttackParametersAndQueryString'
};
/**
 * @export
 */
exports.ExtensionSettingModelCrawlOptionEnum = {
    DoNotCrawl: 'DoNotCrawl',
    Crawl: 'Crawl',
    CrawlOnlyParameter: 'CrawlOnlyParameter'
};
/**
 * Check if a given object implements the ExtensionSettingModel interface.
 */
function instanceOfExtensionSettingModel(value) {
    let isInstance = true;
    isInstance = isInstance && "attackOption" in value;
    isInstance = isInstance && "crawlOption" in value;
    isInstance = isInstance && "extension" in value;
    return isInstance;
}
exports.instanceOfExtensionSettingModel = instanceOfExtensionSettingModel;
function ExtensionSettingModelFromJSON(json) {
    return ExtensionSettingModelFromJSONTyped(json, false);
}
exports.ExtensionSettingModelFromJSON = ExtensionSettingModelFromJSON;
function ExtensionSettingModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'attackOption': json['AttackOption'],
        'crawlOption': json['CrawlOption'],
        'extension': json['Extension'],
    };
}
exports.ExtensionSettingModelFromJSONTyped = ExtensionSettingModelFromJSONTyped;
function ExtensionSettingModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'AttackOption': value.attackOption,
        'CrawlOption': value.crawlOption,
        'Extension': value.extension,
    };
}
exports.ExtensionSettingModelToJSON = ExtensionSettingModelToJSON;
//# sourceMappingURL=ExtensionSettingModel.js.map