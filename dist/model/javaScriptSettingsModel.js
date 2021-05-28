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
exports.JavaScriptSettingsModel = void 0;
/**
* Represents a model for carrying out javascript settings.
*/
class JavaScriptSettingsModel {
    static getAttributeTypeMap() {
        return JavaScriptSettingsModel.attributeTypeMap;
    }
}
exports.JavaScriptSettingsModel = JavaScriptSettingsModel;
JavaScriptSettingsModel.discriminator = undefined;
JavaScriptSettingsModel.attributeTypeMap = [
    {
        "name": "bailThreshold",
        "baseName": "BailThreshold",
        "type": "number"
    },
    {
        "name": "confirmOpenRedirectSimulateTimeout",
        "baseName": "ConfirmOpenRedirectSimulateTimeout",
        "type": "number"
    },
    {
        "name": "confirmXssSimulateTimeout",
        "baseName": "ConfirmXssSimulateTimeout",
        "type": "number"
    },
    {
        "name": "domParserAllowOutOfScopeXmlHttpRequests",
        "baseName": "DomParserAllowOutOfScopeXmlHttpRequests",
        "type": "boolean"
    },
    {
        "name": "domParserDfsLimit",
        "baseName": "DomParserDfsLimit",
        "type": "number"
    },
    {
        "name": "domParserDotify",
        "baseName": "DomParserDotify",
        "type": "boolean"
    },
    {
        "name": "domParserExclusionCssSelector",
        "baseName": "DomParserExclusionCssSelector",
        "type": "string"
    },
    {
        "name": "domParserExtractResources",
        "baseName": "DomParserExtractResources",
        "type": "boolean"
    },
    {
        "name": "domParserFilterColonEvents",
        "baseName": "DomParserFilterColonEvents",
        "type": "boolean"
    },
    {
        "name": "domParserFilterDocumentEvents",
        "baseName": "DomParserFilterDocumentEvents",
        "type": "boolean"
    },
    {
        "name": "domParserIgnoreDocumentEvents",
        "baseName": "DomParserIgnoreDocumentEvents",
        "type": "boolean"
    },
    {
        "name": "domParserLoadUrlTimeout",
        "baseName": "DomParserLoadUrlTimeout",
        "type": "number"
    },
    {
        "name": "domParserMaxOptionElementsPerSelect",
        "baseName": "DomParserMaxOptionElementsPerSelect",
        "type": "number"
    },
    {
        "name": "domParserPersistentJavaScriptCookies",
        "baseName": "DomParserPersistentJavaScriptCookies",
        "type": "string"
    },
    {
        "name": "domParserPreSimulateWait",
        "baseName": "DomParserPreSimulateWait",
        "type": "number"
    },
    {
        "name": "domParserSimulationTimeout",
        "baseName": "DomParserSimulationTimeout",
        "type": "number"
    },
    {
        "name": "enableDomParser",
        "baseName": "EnableDomParser",
        "type": "boolean"
    },
    {
        "name": "intereventTimeout",
        "baseName": "IntereventTimeout",
        "type": "number"
    },
    {
        "name": "skipElementCount",
        "baseName": "SkipElementCount",
        "type": "number"
    },
    {
        "name": "skipThreshold",
        "baseName": "SkipThreshold",
        "type": "number"
    }
];
//# sourceMappingURL=javaScriptSettingsModel.js.map