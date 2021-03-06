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
exports.IssueRequestContentParametersApiModel = void 0;
/**
* Issue request content parameters api response mapping class.
*/
class IssueRequestContentParametersApiModel {
    static getAttributeTypeMap() {
        return IssueRequestContentParametersApiModel.attributeTypeMap;
    }
}
exports.IssueRequestContentParametersApiModel = IssueRequestContentParametersApiModel;
IssueRequestContentParametersApiModel.discriminator = undefined;
IssueRequestContentParametersApiModel.attributeTypeMap = [
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    },
    {
        "name": "value",
        "baseName": "Value",
        "type": "string"
    },
    {
        "name": "typeName",
        "baseName": "TypeName",
        "type": "string"
    },
    {
        "name": "inputType",
        "baseName": "InputType",
        "type": "IssueRequestContentParametersApiModel.InputTypeEnum"
    }
];
(function (IssueRequestContentParametersApiModel) {
    let InputTypeEnum;
    (function (InputTypeEnum) {
        InputTypeEnum[InputTypeEnum["Hidden"] = 'Hidden'] = "Hidden";
        InputTypeEnum[InputTypeEnum["Text"] = 'Text'] = "Text";
        InputTypeEnum[InputTypeEnum["Textarea"] = 'Textarea'] = "Textarea";
        InputTypeEnum[InputTypeEnum["Submit"] = 'Submit'] = "Submit";
        InputTypeEnum[InputTypeEnum["Reset"] = 'Reset'] = "Reset";
        InputTypeEnum[InputTypeEnum["Button"] = 'Button'] = "Button";
        InputTypeEnum[InputTypeEnum["Image"] = 'Image'] = "Image";
        InputTypeEnum[InputTypeEnum["File"] = 'File'] = "File";
        InputTypeEnum[InputTypeEnum["Radio"] = 'Radio'] = "Radio";
        InputTypeEnum[InputTypeEnum["Select"] = 'Select'] = "Select";
        InputTypeEnum[InputTypeEnum["Checkbox"] = 'Checkbox'] = "Checkbox";
        InputTypeEnum[InputTypeEnum["Password"] = 'Password'] = "Password";
        InputTypeEnum[InputTypeEnum["Color"] = 'Color'] = "Color";
        InputTypeEnum[InputTypeEnum["Date"] = 'Date'] = "Date";
        InputTypeEnum[InputTypeEnum["Datetime"] = 'Datetime'] = "Datetime";
        InputTypeEnum[InputTypeEnum["DatetimeLocal"] = 'DatetimeLocal'] = "DatetimeLocal";
        InputTypeEnum[InputTypeEnum["Email"] = 'Email'] = "Email";
        InputTypeEnum[InputTypeEnum["Month"] = 'Month'] = "Month";
        InputTypeEnum[InputTypeEnum["Number"] = 'Number'] = "Number";
        InputTypeEnum[InputTypeEnum["Range"] = 'Range'] = "Range";
        InputTypeEnum[InputTypeEnum["Search"] = 'Search'] = "Search";
        InputTypeEnum[InputTypeEnum["Tel"] = 'Tel'] = "Tel";
        InputTypeEnum[InputTypeEnum["Time"] = 'Time'] = "Time";
        InputTypeEnum[InputTypeEnum["Url"] = 'Url'] = "Url";
        InputTypeEnum[InputTypeEnum["Week"] = 'Week'] = "Week";
        InputTypeEnum[InputTypeEnum["Output"] = 'Output'] = "Output";
    })(InputTypeEnum = IssueRequestContentParametersApiModel.InputTypeEnum || (IssueRequestContentParametersApiModel.InputTypeEnum = {}));
})(IssueRequestContentParametersApiModel = exports.IssueRequestContentParametersApiModel || (exports.IssueRequestContentParametersApiModel = {}));
//# sourceMappingURL=issueRequestContentParametersApiModel.js.map