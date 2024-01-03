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
exports.SecurityCheckGroupModelToJSON = exports.SecurityCheckGroupModelFromJSONTyped = exports.SecurityCheckGroupModelFromJSON = exports.instanceOfSecurityCheckGroupModel = exports.SecurityCheckGroupModelEngineGroupEnum = exports.SecurityCheckGroupModelTypeEnum = void 0;
const runtime_1 = require("../runtime");
const ScanPolicyPatternModel_1 = require("./ScanPolicyPatternModel");
const SecurityCheckSetting_1 = require("./SecurityCheckSetting");
/**
* @export
* @enum {string}
*/
var SecurityCheckGroupModelTypeEnum;
(function (SecurityCheckGroupModelTypeEnum) {
    SecurityCheckGroupModelTypeEnum["Engine"] = "Engine";
    SecurityCheckGroupModelTypeEnum["ResourceModifier"] = "ResourceModifier";
})(SecurityCheckGroupModelTypeEnum = exports.SecurityCheckGroupModelTypeEnum || (exports.SecurityCheckGroupModelTypeEnum = {}));
/**
* @export
* @enum {string}
*/
var SecurityCheckGroupModelEngineGroupEnum;
(function (SecurityCheckGroupModelEngineGroupEnum) {
    SecurityCheckGroupModelEngineGroupEnum["SqlInjection"] = "SqlInjection";
    SecurityCheckGroupModelEngineGroupEnum["Xss"] = "Xss";
    SecurityCheckGroupModelEngineGroupEnum["CommandInjection"] = "CommandInjection";
    SecurityCheckGroupModelEngineGroupEnum["FileInclusion"] = "FileInclusion";
    SecurityCheckGroupModelEngineGroupEnum["Ssrf"] = "Ssrf";
    SecurityCheckGroupModelEngineGroupEnum["Xxe"] = "Xxe";
    SecurityCheckGroupModelEngineGroupEnum["StaticResources"] = "StaticResources";
    SecurityCheckGroupModelEngineGroupEnum["ResourceFinder"] = "ResourceFinder";
    SecurityCheckGroupModelEngineGroupEnum["ApacheStrutsRce"] = "ApacheStrutsRce";
    SecurityCheckGroupModelEngineGroupEnum["CodeEvaluation"] = "CodeEvaluation";
    SecurityCheckGroupModelEngineGroupEnum["CustomScriptChecks"] = "CustomScriptChecks";
    SecurityCheckGroupModelEngineGroupEnum["HeaderInjection"] = "HeaderInjection";
    SecurityCheckGroupModelEngineGroupEnum["NoSqlInjection"] = "NoSqlInjection";
    SecurityCheckGroupModelEngineGroupEnum["WordpressDetection"] = "WordpressDetection";
})(SecurityCheckGroupModelEngineGroupEnum = exports.SecurityCheckGroupModelEngineGroupEnum || (exports.SecurityCheckGroupModelEngineGroupEnum = {}));
/**
 * Check if a given object implements the SecurityCheckGroupModel interface.
 */
function instanceOfSecurityCheckGroupModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfSecurityCheckGroupModel = instanceOfSecurityCheckGroupModel;
function SecurityCheckGroupModelFromJSON(json) {
    return SecurityCheckGroupModelFromJSONTyped(json, false);
}
exports.SecurityCheckGroupModelFromJSON = SecurityCheckGroupModelFromJSON;
function SecurityCheckGroupModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'patterns': !(0, runtime_1.exists)(json, 'Patterns') ? undefined : (json['Patterns'].map(ScanPolicyPatternModel_1.ScanPolicyPatternModelFromJSON)),
        'settings': !(0, runtime_1.exists)(json, 'Settings') ? undefined : (json['Settings'].map(SecurityCheckSetting_1.SecurityCheckSettingFromJSON)),
        'type': !(0, runtime_1.exists)(json, 'Type') ? undefined : json['Type'],
        'engineGroup': !(0, runtime_1.exists)(json, 'EngineGroup') ? undefined : json['EngineGroup'],
        'description': !(0, runtime_1.exists)(json, 'Description') ? undefined : json['Description'],
        'enabled': !(0, runtime_1.exists)(json, 'Enabled') ? undefined : json['Enabled'],
        'id': !(0, runtime_1.exists)(json, 'Id') ? undefined : json['Id'],
        'name': !(0, runtime_1.exists)(json, 'Name') ? undefined : json['Name'],
    };
}
exports.SecurityCheckGroupModelFromJSONTyped = SecurityCheckGroupModelFromJSONTyped;
function SecurityCheckGroupModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Patterns': value.patterns === undefined ? undefined : (value.patterns.map(ScanPolicyPatternModel_1.ScanPolicyPatternModelToJSON)),
        'Settings': value.settings === undefined ? undefined : (value.settings.map(SecurityCheckSetting_1.SecurityCheckSettingToJSON)),
        'Type': value.type,
        'EngineGroup': value.engineGroup,
        'Description': value.description,
        'Enabled': value.enabled,
        'Id': value.id,
        'Name': value.name,
    };
}
exports.SecurityCheckGroupModelToJSON = SecurityCheckGroupModelToJSON;
//# sourceMappingURL=SecurityCheckGroupModel.js.map