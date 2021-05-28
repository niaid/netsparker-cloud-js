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
/**
* Represents a model for carrying out form value settings.
*/
export declare class FormValueSettingModel {
    /**
    * Gets or sets a value indicating whether force option is enabled.
    */
    'force'?: boolean;
    /**
    * Gets or sets the match type.
    */
    'match'?: FormValueSettingModel.MatchEnum;
    /**
    * Gets or sets the match target.
    */
    'matchTarget'?: Array<FormValueSettingModel.MatchTargetEnum>;
    /**
    * Gets or sets the match target.
    */
    'matchTargetValue': FormValueSettingModel.MatchTargetValueEnum;
    /**
    * Gets or sets the name.
    */
    'name': string;
    /**
    * Gets or sets the pattern.
    */
    'pattern'?: string;
    /**
    * Gets or sets the type.
    */
    'type'?: string;
    /**
    * Gets or sets the value.
    */
    'value': string;
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
export declare namespace FormValueSettingModel {
    enum MatchEnum {
        RegEx,
        Exact,
        Contains,
        Starts,
        Ends
    }
    enum MatchTargetEnum {
        Name,
        Label,
        Placeholder,
        Id
    }
    enum MatchTargetValueEnum {
        Name,
        Label,
        Placeholder,
        Id
    }
}