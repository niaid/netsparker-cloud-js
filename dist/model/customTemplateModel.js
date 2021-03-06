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
exports.CustomTemplateModel = void 0;
/**
* Vulnerability template extended model.
*/
class CustomTemplateModel {
    static getAttributeTypeMap() {
        return CustomTemplateModel.attributeTypeMap;
    }
}
exports.CustomTemplateModel = CustomTemplateModel;
CustomTemplateModel.discriminator = undefined;
CustomTemplateModel.attributeTypeMap = [
    {
        "name": "sourceTemplateId",
        "baseName": "source_template_id",
        "type": "string"
    },
    {
        "name": "title",
        "baseName": "title",
        "type": "string"
    },
    {
        "name": "description",
        "baseName": "description",
        "type": "string"
    },
    {
        "name": "remediation",
        "baseName": "remediation",
        "type": "string"
    },
    {
        "name": "severity",
        "baseName": "severity",
        "type": "number"
    },
    {
        "name": "template",
        "baseName": "template",
        "type": "CustomTemplateContentModel"
    }
];
//# sourceMappingURL=customTemplateModel.js.map