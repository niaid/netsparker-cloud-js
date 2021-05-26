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

import { RequestFile } from './models';

/**
* Represents a model for carrying out attacking settings.
*/
export class AttackingSettingModel {
    /**
    * Gets or sets the anti CSRF token names.
    */
    'antiCsrfTokenNames'?: string;
    /**
    * Gets or sets a value indicating whether parameter name attacking is enabled.
    */
    'attackParameterName'?: boolean;
    /**
    * Gets or sets a value indicating whether attacking to Referer header is enabled.
    */
    'attackRefererHeader'?: boolean;
    /**
    * Gets or sets a value indicating whether attacking to User-Agent header is enabled.
    */
    'attackUserAgentHeader'?: boolean;
    /**
    * Gets or sets a value indicating whether attacking to cookies is enabled.
    */
    'attackCookies'?: boolean;
    /**
    * Gets or sets the maximum parameters to attack.
    */
    'maxParametersToAttack'?: number;
    /**
    * Gets or sets a value indicating whether optimization for recurring parameters is enabled.
    */
    'optimizeAttacksToRecurringParameters'?: boolean;
    /**
    * Gets or sets a value indicating whether optimization for header attacks is enabled.
    */
    'optimizeHeaderAttacks'?: boolean;
    /**
    * Gets or sets a value indicating whether proof generation is enabled.
    */
    'proofGenerationEnabled'?: boolean;
    /**
    * Gets or sets the page attack limit for links containing recurring parameters.
    */
    'recurringParametersPageAttackLimit'?: number;
    /**
    * Gets or sets a value indicating whether extra parameters should be used.
    */
    'useExtraParameters'?: boolean;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
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
        }    ];

    static getAttributeTypeMap() {
        return AttackingSettingModel.attributeTypeMap;
    }
}

