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

import { exists, mapValues } from '../runtime';
import type { ScanPolicyPatternModel } from './ScanPolicyPatternModel';
import {
    ScanPolicyPatternModelFromJSON,
    ScanPolicyPatternModelFromJSONTyped,
    ScanPolicyPatternModelToJSON,
} from './ScanPolicyPatternModel';
import type { SecurityCheckSetting } from './SecurityCheckSetting';
import {
    SecurityCheckSettingFromJSON,
    SecurityCheckSettingFromJSONTyped,
    SecurityCheckSettingToJSON,
} from './SecurityCheckSetting';

/**
 * Represents a model for carrying out security check groups.
 * @export
 * @interface SecurityCheckGroupModel
 */
export interface SecurityCheckGroupModel {
    /**
     * Gets or sets the scan policy patterns.
     * @type {Array<ScanPolicyPatternModel>}
     * @memberof SecurityCheckGroupModel
     */
    patterns?: Array<ScanPolicyPatternModel>;
    /**
     * Gets or sets the settings.
     * @type {Array<SecurityCheckSetting>}
     * @memberof SecurityCheckGroupModel
     */
    settings?: Array<SecurityCheckSetting>;
    /**
     * Gets or sets the security check group type.
     * @type {string}
     * @memberof SecurityCheckGroupModel
     */
    type?: SecurityCheckGroupModelTypeEnum;
    /**
     * Engine group identifier
     * @type {string}
     * @memberof SecurityCheckGroupModel
     */
    engineGroup?: SecurityCheckGroupModelEngineGroupEnum;
    /**
     * Gets or sets the description of the security check.
     * @type {string}
     * @memberof SecurityCheckGroupModel
     */
    description?: string;
    /**
     * Gets or sets a value indicating whether this instance is enabled.
     * @type {boolean}
     * @memberof SecurityCheckGroupModel
     */
    enabled?: boolean;
    /**
     * Gets or sets the id of the security check.
     * @type {string}
     * @memberof SecurityCheckGroupModel
     */
    id?: string;
    /**
     * Gets or sets the name of the security check.
     * @type {string}
     * @memberof SecurityCheckGroupModel
     */
    name?: string;
}


/**
 * @export
 */
export const SecurityCheckGroupModelTypeEnum = {
    Engine: 'Engine',
    ResourceModifier: 'ResourceModifier'
} as const;
export type SecurityCheckGroupModelTypeEnum = typeof SecurityCheckGroupModelTypeEnum[keyof typeof SecurityCheckGroupModelTypeEnum];

/**
 * @export
 */
export const SecurityCheckGroupModelEngineGroupEnum = {
    SqlInjection: 'SqlInjection',
    Xss: 'Xss',
    CommandInjection: 'CommandInjection',
    FileInclusion: 'FileInclusion',
    Ssrf: 'Ssrf',
    Xxe: 'Xxe',
    StaticResources: 'StaticResources',
    ResourceFinder: 'ResourceFinder',
    ApacheStrutsRce: 'ApacheStrutsRce',
    CodeEvaluation: 'CodeEvaluation',
    CustomScriptChecks: 'CustomScriptChecks',
    HeaderInjection: 'HeaderInjection',
    NoSqlInjection: 'NoSqlInjection',
    WordpressDetection: 'WordpressDetection'
} as const;
export type SecurityCheckGroupModelEngineGroupEnum = typeof SecurityCheckGroupModelEngineGroupEnum[keyof typeof SecurityCheckGroupModelEngineGroupEnum];


/**
 * Check if a given object implements the SecurityCheckGroupModel interface.
 */
export function instanceOfSecurityCheckGroupModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function SecurityCheckGroupModelFromJSON(json: any): SecurityCheckGroupModel {
    return SecurityCheckGroupModelFromJSONTyped(json, false);
}

export function SecurityCheckGroupModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): SecurityCheckGroupModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'patterns': !exists(json, 'Patterns') ? undefined : ((json['Patterns'] as Array<any>).map(ScanPolicyPatternModelFromJSON)),
        'settings': !exists(json, 'Settings') ? undefined : ((json['Settings'] as Array<any>).map(SecurityCheckSettingFromJSON)),
        'type': !exists(json, 'Type') ? undefined : json['Type'],
        'engineGroup': !exists(json, 'EngineGroup') ? undefined : json['EngineGroup'],
        'description': !exists(json, 'Description') ? undefined : json['Description'],
        'enabled': !exists(json, 'Enabled') ? undefined : json['Enabled'],
        'id': !exists(json, 'Id') ? undefined : json['Id'],
        'name': !exists(json, 'Name') ? undefined : json['Name'],
    };
}

export function SecurityCheckGroupModelToJSON(value?: SecurityCheckGroupModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Patterns': value.patterns === undefined ? undefined : ((value.patterns as Array<any>).map(ScanPolicyPatternModelToJSON)),
        'Settings': value.settings === undefined ? undefined : ((value.settings as Array<any>).map(SecurityCheckSettingToJSON)),
        'Type': value.type,
        'EngineGroup': value.engineGroup,
        'Description': value.description,
        'Enabled': value.enabled,
        'Id': value.id,
        'Name': value.name,
    };
}

