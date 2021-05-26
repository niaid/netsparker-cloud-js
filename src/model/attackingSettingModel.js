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
exports.AttackingSettingModel = void 0;
/**
* Represents a model for carrying out attacking settings.
*/
class AttackingSettingModel {
    static getAttributeTypeMap() {
        return AttackingSettingModel.attributeTypeMap;
    }
}
exports.AttackingSettingModel = AttackingSettingModel;
AttackingSettingModel.discriminator = undefined;
AttackingSettingModel.attributeTypeMap = [
    {
        "name": "antiCsrfTokenNames",
        "baseName": "AntiCsrfTokenNames",
        "type": "string"
    },
    {
        "name": "attackParameterName",
        "baseName": "AttackParameterName",
        "type": "boolean"
    },
    {
        "name": "attackRefererHeader",
        "baseName": "AttackRefererHeader",
        "type": "boolean"
    },
    {
        "name": "attackUserAgentHeader",
        "baseName": "AttackUserAgentHeader",
        "type": "boolean"
    },
    {
        "name": "attackCookies",
        "baseName": "AttackCookies",
        "type": "boolean"
    },
    {
        "name": "maxParametersToAttack",
        "baseName": "MaxParametersToAttack",
        "type": "number"
    },
    {
        "name": "optimizeAttacksToRecurringParameters",
        "baseName": "OptimizeAttacksToRecurringParameters",
        "type": "boolean"
    },
    {
        "name": "optimizeHeaderAttacks",
        "baseName": "OptimizeHeaderAttacks",
        "type": "boolean"
    },
    {
        "name": "proofGenerationEnabled",
        "baseName": "ProofGenerationEnabled",
        "type": "boolean"
    },
    {
        "name": "recurringParametersPageAttackLimit",
        "baseName": "RecurringParametersPageAttackLimit",
        "type": "number"
    },
    {
        "name": "useExtraParameters",
        "baseName": "UseExtraParameters",
        "type": "boolean"
    }
];
//# sourceMappingURL=attackingSettingModel.js.map