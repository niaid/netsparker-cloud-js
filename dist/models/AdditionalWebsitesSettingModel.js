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
exports.AdditionalWebsitesSettingModelToJSON = exports.AdditionalWebsitesSettingModelFromJSONTyped = exports.AdditionalWebsitesSettingModelFromJSON = exports.instanceOfAdditionalWebsitesSettingModel = void 0;
const AdditionalWebsiteModel_1 = require("./AdditionalWebsiteModel");
/**
 * Check if a given object implements the AdditionalWebsitesSettingModel interface.
 */
function instanceOfAdditionalWebsitesSettingModel(value) {
    return true;
}
exports.instanceOfAdditionalWebsitesSettingModel = instanceOfAdditionalWebsitesSettingModel;
function AdditionalWebsitesSettingModelFromJSON(json) {
    return AdditionalWebsitesSettingModelFromJSONTyped(json, false);
}
exports.AdditionalWebsitesSettingModelFromJSON = AdditionalWebsitesSettingModelFromJSON;
function AdditionalWebsitesSettingModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'websites': json['Websites'] == null ? undefined : (json['Websites'].map(AdditionalWebsiteModel_1.AdditionalWebsiteModelFromJSON)),
    };
}
exports.AdditionalWebsitesSettingModelFromJSONTyped = AdditionalWebsitesSettingModelFromJSONTyped;
function AdditionalWebsitesSettingModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Websites': value['websites'] == null ? undefined : (value['websites'].map(AdditionalWebsiteModel_1.AdditionalWebsiteModelToJSON)),
    };
}
exports.AdditionalWebsitesSettingModelToJSON = AdditionalWebsitesSettingModelToJSON;
//# sourceMappingURL=AdditionalWebsitesSettingModel.js.map