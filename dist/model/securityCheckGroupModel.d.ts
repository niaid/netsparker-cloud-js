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
import { ScanPolicyPatternModel } from './scanPolicyPatternModel';
import { SecurityCheckSetting } from './securityCheckSetting';
/**
* Represents a model for carrying out security check groups.
*/
export declare class SecurityCheckGroupModel {
    /**
    * Gets or sets the scan policy patterns.
    */
    'patterns'?: Array<ScanPolicyPatternModel>;
    /**
    * Gets or sets the settings.
    */
    'settings'?: Array<SecurityCheckSetting>;
    /**
    * Gets or sets the security check group type.
    */
    'type'?: SecurityCheckGroupModel.TypeEnum;
    /**
    * Engine group identifier
    */
    'engineGroup'?: SecurityCheckGroupModel.EngineGroupEnum;
    /**
    * Gets or sets the description of the security check.
    */
    'description'?: string;
    /**
    * Gets or sets a value indicating whether this instance is enabled.
    */
    'enabled'?: boolean;
    /**
    * Gets or sets the id of the security check.
    */
    'id'?: string;
    /**
    * Gets or sets the name of the security check.
    */
    'name'?: string;
    static discriminator: string | undefined;
    static attributeTypeMap: Array<{
        name: string;
        baseName: string;
        type: string;
    }>;
    static getAttributeTypeMap(): {
        name: string;
        baseName: string;
        type: string;
    }[];
}
export declare namespace SecurityCheckGroupModel {
    enum TypeEnum {
        Engine,
        ResourceModifier
    }
    enum EngineGroupEnum {
        SqlInjection,
        Xss,
        CommandInjection,
        FileInclusion,
        Ssrf,
        Xxe,
        StaticResources,
        ResourceFinder,
        ApacheStrutsRce,
        CodeEvaluation,
        CustomScriptChecks,
        HeaderInjection
    }
}