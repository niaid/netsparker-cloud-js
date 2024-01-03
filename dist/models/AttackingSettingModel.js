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
import { exists } from '../runtime';
/**
 * Check if a given object implements the AttackingSettingModel interface.
 */
export function instanceOfAttackingSettingModel(value) {
    let isInstance = true;
    return isInstance;
}
export function AttackingSettingModelFromJSON(json) {
    return AttackingSettingModelFromJSONTyped(json, false);
}
export function AttackingSettingModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'antiCsrfTokenNames': !exists(json, 'AntiCsrfTokenNames') ? undefined : json['AntiCsrfTokenNames'],
        'attackParameterName': !exists(json, 'AttackParameterName') ? undefined : json['AttackParameterName'],
        'attackRefererHeader': !exists(json, 'AttackRefererHeader') ? undefined : json['AttackRefererHeader'],
        'attackUserAgentHeader': !exists(json, 'AttackUserAgentHeader') ? undefined : json['AttackUserAgentHeader'],
        'attackCookies': !exists(json, 'AttackCookies') ? undefined : json['AttackCookies'],
        'maxParametersToAttack': !exists(json, 'MaxParametersToAttack') ? undefined : json['MaxParametersToAttack'],
        'optimizeAttacksToRecurringParameters': !exists(json, 'OptimizeAttacksToRecurringParameters') ? undefined : json['OptimizeAttacksToRecurringParameters'],
        'optimizeHeaderAttacks': !exists(json, 'OptimizeHeaderAttacks') ? undefined : json['OptimizeHeaderAttacks'],
        'overrideVersionVulnerabilitySeverity': !exists(json, 'OverrideVersionVulnerabilitySeverity') ? undefined : json['OverrideVersionVulnerabilitySeverity'],
        'proofGenerationEnabled': !exists(json, 'ProofGenerationEnabled') ? undefined : json['ProofGenerationEnabled'],
        'recurringParametersPageAttackLimit': !exists(json, 'RecurringParametersPageAttackLimit') ? undefined : json['RecurringParametersPageAttackLimit'],
        'useExtraParameters': !exists(json, 'UseExtraParameters') ? undefined : json['UseExtraParameters'],
        'attackCsrfToken': !exists(json, 'AttackCsrfToken') ? undefined : json['AttackCsrfToken'],
    };
}
export function AttackingSettingModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'AntiCsrfTokenNames': value.antiCsrfTokenNames,
        'AttackParameterName': value.attackParameterName,
        'AttackRefererHeader': value.attackRefererHeader,
        'AttackUserAgentHeader': value.attackUserAgentHeader,
        'AttackCookies': value.attackCookies,
        'MaxParametersToAttack': value.maxParametersToAttack,
        'OptimizeAttacksToRecurringParameters': value.optimizeAttacksToRecurringParameters,
        'OptimizeHeaderAttacks': value.optimizeHeaderAttacks,
        'OverrideVersionVulnerabilitySeverity': value.overrideVersionVulnerabilitySeverity,
        'ProofGenerationEnabled': value.proofGenerationEnabled,
        'RecurringParametersPageAttackLimit': value.recurringParametersPageAttackLimit,
        'UseExtraParameters': value.useExtraParameters,
        'AttackCsrfToken': value.attackCsrfToken,
    };
}
//# sourceMappingURL=AttackingSettingModel.js.map