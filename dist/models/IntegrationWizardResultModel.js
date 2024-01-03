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
exports.IntegrationWizardResultModelToJSON = exports.IntegrationWizardResultModelFromJSONTyped = exports.IntegrationWizardResultModelFromJSON = exports.instanceOfIntegrationWizardResultModel = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the IntegrationWizardResultModel interface.
 */
function instanceOfIntegrationWizardResultModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfIntegrationWizardResultModel = instanceOfIntegrationWizardResultModel;
function IntegrationWizardResultModelFromJSON(json) {
    return IntegrationWizardResultModelFromJSONTyped(json, false);
}
exports.IntegrationWizardResultModelFromJSON = IntegrationWizardResultModelFromJSON;
function IntegrationWizardResultModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'status': !(0, runtime_1.exists)(json, 'Status') ? undefined : json['Status'],
        'errorMessage': !(0, runtime_1.exists)(json, 'ErrorMessage') ? undefined : json['ErrorMessage'],
    };
}
exports.IntegrationWizardResultModelFromJSONTyped = IntegrationWizardResultModelFromJSONTyped;
function IntegrationWizardResultModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Status': value.status,
        'ErrorMessage': value.errorMessage,
    };
}
exports.IntegrationWizardResultModelToJSON = IntegrationWizardResultModelToJSON;
//# sourceMappingURL=IntegrationWizardResultModel.js.map