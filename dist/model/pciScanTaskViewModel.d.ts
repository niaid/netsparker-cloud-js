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
* Pci Scan Task view model
*/
export declare class PciScanTaskViewModel {
    /**
    * Gets or sets the name
    */
    'name'?: string;
    /**
    * Gets or sets the progress for scan task
    */
    'progress'?: number;
    /**
    * Gets or sets the scan state
    */
    'scanState'?: PciScanTaskViewModel.ScanStateEnum;
    /**
    * Gets or sets the compliance status. This will be setted when pci scan task is done
    */
    'complianceStatus'?: PciScanTaskViewModel.ComplianceStatusEnum;
    /**
    * Gets or sets the end date
    */
    'endDate'?: Date;
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
export declare namespace PciScanTaskViewModel {
    enum ScanStateEnum {
        New,
        Running,
        Stopped,
        Deleted,
        Done
    }
    enum ComplianceStatusEnum {
        Scanning,
        Passed,
        Failed
    }
}