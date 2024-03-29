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
exports.CustomTemplateModelToJSON = exports.CustomTemplateModelFromJSONTyped = exports.CustomTemplateModelFromJSON = exports.instanceOfCustomTemplateModel = void 0;
const runtime_1 = require("../runtime");
const CustomTemplateContentModel_1 = require("./CustomTemplateContentModel");
/**
 * Check if a given object implements the CustomTemplateModel interface.
 */
function instanceOfCustomTemplateModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfCustomTemplateModel = instanceOfCustomTemplateModel;
function CustomTemplateModelFromJSON(json) {
    return CustomTemplateModelFromJSONTyped(json, false);
}
exports.CustomTemplateModelFromJSON = CustomTemplateModelFromJSON;
function CustomTemplateModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'sourceTemplateId': !(0, runtime_1.exists)(json, 'source_template_id') ? undefined : json['source_template_id'],
        'title': !(0, runtime_1.exists)(json, 'title') ? undefined : json['title'],
        'description': !(0, runtime_1.exists)(json, 'description') ? undefined : json['description'],
        'remediation': !(0, runtime_1.exists)(json, 'remediation') ? undefined : json['remediation'],
        'severity': !(0, runtime_1.exists)(json, 'severity') ? undefined : json['severity'],
        'template': !(0, runtime_1.exists)(json, 'template') ? undefined : (0, CustomTemplateContentModel_1.CustomTemplateContentModelFromJSON)(json['template']),
    };
}
exports.CustomTemplateModelFromJSONTyped = CustomTemplateModelFromJSONTyped;
function CustomTemplateModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'source_template_id': value.sourceTemplateId,
        'title': value.title,
        'description': value.description,
        'remediation': value.remediation,
        'severity': value.severity,
        'template': (0, CustomTemplateContentModel_1.CustomTemplateContentModelToJSON)(value.template),
    };
}
exports.CustomTemplateModelToJSON = CustomTemplateModelToJSON;
//# sourceMappingURL=CustomTemplateModel.js.map