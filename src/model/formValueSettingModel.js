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
/**
* Represents a model for carrying out form value settings.
*/
class FormValueSettingModel {
    static getAttributeTypeMap() {
        return FormValueSettingModel.attributeTypeMap;
    }
}
FormValueSettingModel.discriminator = undefined;
FormValueSettingModel.attributeTypeMap = [
    {
        "name": "force",
        "baseName": "Force",
        "type": "boolean"
    },
    {
        "name": "match",
        "baseName": "Match",
        "type": "FormValueSettingModel.MatchEnum"
    },
    {
        "name": "matchTarget",
        "baseName": "MatchTarget",
        "type": "Array<FormValueSettingModel.MatchTargetEnum>"
    },
    {
        "name": "matchTargetValue",
        "baseName": "MatchTargetValue",
        "type": "FormValueSettingModel.MatchTargetValueEnum"
    },
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    },
    {
        "name": "pattern",
        "baseName": "Pattern",
        "type": "string"
    },
    {
        "name": "type",
        "baseName": "Type",
        "type": "string"
    },
    {
        "name": "value",
        "baseName": "Value",
        "type": "string"
    }
];
exports.FormValueSettingModel = FormValueSettingModel;
(function (FormValueSettingModel) {
    let MatchEnum;
    (function (MatchEnum) {
        MatchEnum[MatchEnum["RegEx"] = 'RegEx'] = "RegEx";
        MatchEnum[MatchEnum["Exact"] = 'Exact'] = "Exact";
        MatchEnum[MatchEnum["Contains"] = 'Contains'] = "Contains";
        MatchEnum[MatchEnum["Starts"] = 'Starts'] = "Starts";
        MatchEnum[MatchEnum["Ends"] = 'Ends'] = "Ends";
    })(MatchEnum = FormValueSettingModel.MatchEnum || (FormValueSettingModel.MatchEnum = {}));
    let MatchTargetEnum;
    (function (MatchTargetEnum) {
        MatchTargetEnum[MatchTargetEnum["Name"] = 'Name'] = "Name";
        MatchTargetEnum[MatchTargetEnum["Label"] = 'Label'] = "Label";
        MatchTargetEnum[MatchTargetEnum["Placeholder"] = 'Placeholder'] = "Placeholder";
        MatchTargetEnum[MatchTargetEnum["Id"] = 'Id'] = "Id";
    })(MatchTargetEnum = FormValueSettingModel.MatchTargetEnum || (FormValueSettingModel.MatchTargetEnum = {}));
    let MatchTargetValueEnum;
    (function (MatchTargetValueEnum) {
        MatchTargetValueEnum[MatchTargetValueEnum["Name"] = 'Name'] = "Name";
        MatchTargetValueEnum[MatchTargetValueEnum["Label"] = 'Label'] = "Label";
        MatchTargetValueEnum[MatchTargetValueEnum["Placeholder"] = 'Placeholder'] = "Placeholder";
        MatchTargetValueEnum[MatchTargetValueEnum["Id"] = 'Id'] = "Id";
    })(MatchTargetValueEnum = FormValueSettingModel.MatchTargetValueEnum || (FormValueSettingModel.MatchTargetValueEnum = {}));
})(FormValueSettingModel = exports.FormValueSettingModel || (exports.FormValueSettingModel = {}));
//# sourceMappingURL=formValueSettingModel.js.map