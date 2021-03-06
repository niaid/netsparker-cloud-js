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
* Represents a model for carrying out an update incremental scan notification data
*/
export declare class UpdateScheduledIncrementalScanApiModel {
    /**
    * Gets or sets a value indicating whether scheduled scan is disabled.
    */
    'disabled'?: boolean;
    /**
    * Gets or sets the scan identifier.
    */
    'id': string;
    /**
    * Gets or sets a value indicating whether max scan duration is enabled.
    */
    'isMaxScanDurationEnabled'?: boolean;
    /**
    * Gets or sets the maximum duration of the scan in hours.
    */
    'maxScanDuration'?: number;
    /**
    * Gets or sets the name.
    */
    'name': string;
    /**
    * Gets or sets the next execution time.  Date string must be in the same format as in the account settings.
    */
    'nextExecutionTime': string;
    /**
    * Gets or sets the run interval of scheduled scan.
    */
    'scheduleRunType': UpdateScheduledIncrementalScanApiModel.ScheduleRunTypeEnum;
    /**
    * Gets or sets the agent name.
    */
    'agentName'?: string;
    /**
    * Gets or sets the base scan identifier.
    */
    'baseScanId': string;
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
export declare namespace UpdateScheduledIncrementalScanApiModel {
    enum ScheduleRunTypeEnum {
        Once,
        Daily,
        Weekly,
        Monthly,
        Quarterly,
        Biannually,
        Yearly,
        Custom
    }
}
