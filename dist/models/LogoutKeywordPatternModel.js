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
exports.LogoutKeywordPatternModelToJSON = exports.LogoutKeywordPatternModelFromJSONTyped = exports.LogoutKeywordPatternModelFromJSON = exports.instanceOfLogoutKeywordPatternModel = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the LogoutKeywordPatternModel interface.
 */
function instanceOfLogoutKeywordPatternModel(value) {
    let isInstance = true;
    isInstance = isInstance && "pattern" in value;
    return isInstance;
}
exports.instanceOfLogoutKeywordPatternModel = instanceOfLogoutKeywordPatternModel;
function LogoutKeywordPatternModelFromJSON(json) {
    return LogoutKeywordPatternModelFromJSONTyped(json, false);
}
exports.LogoutKeywordPatternModelFromJSON = LogoutKeywordPatternModelFromJSON;
function LogoutKeywordPatternModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'pattern': json['Pattern'],
        'regex': !(0, runtime_1.exists)(json, 'Regex') ? undefined : json['Regex'],
    };
}
exports.LogoutKeywordPatternModelFromJSONTyped = LogoutKeywordPatternModelFromJSONTyped;
function LogoutKeywordPatternModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Pattern': value.pattern,
        'Regex': value.regex,
    };
}
exports.LogoutKeywordPatternModelToJSON = LogoutKeywordPatternModelToJSON;
//# sourceMappingURL=LogoutKeywordPatternModel.js.map