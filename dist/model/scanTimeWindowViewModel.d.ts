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
import { ScanTimeWindowItemViewModel } from './scanTimeWindowItemViewModel';
/**
* Represents a model for carrying out scan time window settings.
*/
export declare class ScanTimeWindowViewModel {
    /**
    * Gets or sets a value indicating whether scan time window is enabled.
    */
    'isEnabled'?: boolean;
    /**
    * Gets or sets a value indicating whether scan time window is enabled.
    */
    'isEnabledForWebsite'?: boolean;
    /**
    * Gets or sets a value indicating whether scan time window is enabled.
    */
    'isEnabledForWebsiteGroup'?: boolean;
    /**
    * Gets or sets the time range items.
    */
    'items'?: Array<ScanTimeWindowItemViewModel>;
    /**
    * Scan time window created time zone.
    */
    'timeZone'?: string;
    /**
    * Gets or sets the scan create type.
    */
    'scanCreateType'?: ScanTimeWindowViewModel.ScanCreateTypeEnum;
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
export declare namespace ScanTimeWindowViewModel {
    enum ScanCreateTypeEnum {
        Website,
        WebsiteGroup
    }
}
