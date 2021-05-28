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
exports.UrlRewriteSetting = void 0;
/**
* Represents a class that carries out url rewrite settings.
*/
class UrlRewriteSetting {
    static getAttributeTypeMap() {
        return UrlRewriteSetting.attributeTypeMap;
    }
}
exports.UrlRewriteSetting = UrlRewriteSetting;
UrlRewriteSetting.discriminator = undefined;
UrlRewriteSetting.attributeTypeMap = [
    {
        "name": "enableHeuristicChecksInCustomUrlRewrite",
        "baseName": "EnableHeuristicChecksInCustomUrlRewrite",
        "type": "boolean"
    },
    {
        "name": "maxDynamicSignatures",
        "baseName": "MaxDynamicSignatures",
        "type": "number"
    },
    {
        "name": "subPathMaxDynamicSignatures",
        "baseName": "SubPathMaxDynamicSignatures",
        "type": "number"
    },
    {
        "name": "urlRewriteAnalyzableExtensions",
        "baseName": "UrlRewriteAnalyzableExtensions",
        "type": "string"
    },
    {
        "name": "urlRewriteBlockSeparators",
        "baseName": "UrlRewriteBlockSeparators",
        "type": "string"
    },
    {
        "name": "urlRewriteMode",
        "baseName": "UrlRewriteMode",
        "type": "UrlRewriteSetting.UrlRewriteModeEnum"
    },
    {
        "name": "urlRewriteRules",
        "baseName": "UrlRewriteRules",
        "type": "Array<UrlRewriteRuleModel>"
    },
    {
        "name": "urlRewriteExcludedLinks",
        "baseName": "UrlRewriteExcludedLinks",
        "type": "Array<UrlRewriteExcludedPathModel>"
    }
];
(function (UrlRewriteSetting) {
    let UrlRewriteModeEnum;
    (function (UrlRewriteModeEnum) {
        UrlRewriteModeEnum[UrlRewriteModeEnum["None"] = 'None'] = "None";
        UrlRewriteModeEnum[UrlRewriteModeEnum["Heuristic"] = 'Heuristic'] = "Heuristic";
        UrlRewriteModeEnum[UrlRewriteModeEnum["Custom"] = 'Custom'] = "Custom";
    })(UrlRewriteModeEnum = UrlRewriteSetting.UrlRewriteModeEnum || (UrlRewriteSetting.UrlRewriteModeEnum = {}));
})(UrlRewriteSetting = exports.UrlRewriteSetting || (exports.UrlRewriteSetting = {}));
//# sourceMappingURL=urlRewriteSetting.js.map