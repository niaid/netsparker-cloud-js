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
* Represents a scan time window item.
*/
export declare class ScanTimeWindowItemModel {
    /**
    * Gets or sets the day.
    */
    'day'?: ScanTimeWindowItemModel.DayEnum;
    /**
    * Gets or sets the left side of the time range.  Default: 00:00
    */
    'from'?: string;
    /**
    * Gets or sets a value indicating whether scanning is allowed or not.  Default: true
    */
    'scanningAllowed'?: boolean;
    /**
    * Gets or sets the right side of the time range.  Default: 23:59
    */
    'to'?: string;
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
export declare namespace ScanTimeWindowItemModel {
    enum DayEnum {
        Sunday,
        Monday,
        Tuesday,
        Wednesday,
        Thursday,
        Friday,
        Saturday
    }
}