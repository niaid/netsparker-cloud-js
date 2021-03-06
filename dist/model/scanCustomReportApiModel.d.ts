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
* Represents a model for carrying scan custom report parameters.
*/
export declare class ScanCustomReportApiModel {
    /**
    * If set to true, HTTP response data will be excluded from the report results. This parameter can only be  used for vulnerabilities XML report.  Default: false
    */
    'excludeIgnoreds'?: boolean;
    /**
    * Gets or sets the scan identifier.
    */
    'id': string;
    /**
    * If set to true, HTTP response data will be included only confirmed vulnerabilities to report results. This  parameter can only be  used for vulnerabilities reports.  Default: false
    */
    'onlyConfirmedVulnerabilities'?: boolean;
    /**
    * If set to true, HTTP response data will be included only unconfirmed vulnerabilities to report results. This  parameter can only be  used for vulnerabilities reports.  Default: false
    */
    'onlyUnconfirmedVulnerabilities'?: boolean;
    /**
    * Gets or sets report name. Report name also keeps report type in it.
    */
    'reportName': string;
    /**
    * Gets or sets the report format.
    */
    'reportFormat'?: ScanCustomReportApiModel.ReportFormatEnum;
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
export declare namespace ScanCustomReportApiModel {
    enum ReportFormatEnum {
        Xml,
        Csv,
        Pdf,
        Html,
        Txt,
        Json
    }
}
