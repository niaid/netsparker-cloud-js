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
exports.BruteForceSettingModel = void 0;
/**
* Represents a model for carrying out authentication brute force settings.
*/
class BruteForceSettingModel {
    static getAttributeTypeMap() {
        return BruteForceSettingModel.attributeTypeMap;
    }
}
exports.BruteForceSettingModel = BruteForceSettingModel;
BruteForceSettingModel.discriminator = undefined;
BruteForceSettingModel.attributeTypeMap = [
    {
        "name": "enableAuthBruteForce",
        "baseName": "EnableAuthBruteForce",
        "type": "boolean"
    },
    {
        "name": "maxBruteForce",
        "baseName": "MaxBruteForce",
        "type": "number"
    }
];
//# sourceMappingURL=bruteForceSettingModel.js.map