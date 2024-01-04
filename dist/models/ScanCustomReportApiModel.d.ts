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
/**
 * Represents a model for carrying scan custom report parameters.
 * @export
 * @interface ScanCustomReportApiModel
 */
export interface ScanCustomReportApiModel {
    /**
     * If set to true, HTTP response data will be excluded from the report results. This parameter can only be
     * used for vulnerabilities XML report.
     * Default: false
     * @type {boolean}
     * @memberof ScanCustomReportApiModel
     */
    excludeIgnoreds?: boolean;
    /**
     * Gets or sets the scan identifier.
     * @type {string}
     * @memberof ScanCustomReportApiModel
     */
    id: string;
    /**
     * If set to true, HTTP response data will be included only confirmed vulnerabilities to report results. This
     * parameter can only be
     * used for vulnerabilities reports.
     * Default: false
     * @type {boolean}
     * @memberof ScanCustomReportApiModel
     */
    onlyConfirmedVulnerabilities?: boolean;
    /**
     * If set to true, HTTP response data will be included only unconfirmed vulnerabilities to report results. This
     * parameter can only be
     * used for vulnerabilities reports.
     * Default: false
     * @type {boolean}
     * @memberof ScanCustomReportApiModel
     */
    onlyUnconfirmedVulnerabilities?: boolean;
    /**
     * Gets or sets report name. Report name also keeps report type in it.
     * @type {string}
     * @memberof ScanCustomReportApiModel
     */
    reportName: string;
    /**
     * Gets or sets the report format.
     * @type {string}
     * @memberof ScanCustomReportApiModel
     */
    reportFormat?: ScanCustomReportApiModelReportFormatEnum;
}
/**
 * @export
 */
export declare const ScanCustomReportApiModelReportFormatEnum: {
    readonly Xml: "Xml";
    readonly Csv: "Csv";
    readonly Pdf: "Pdf";
    readonly Html: "Html";
    readonly Txt: "Txt";
    readonly Json: "Json";
};
export type ScanCustomReportApiModelReportFormatEnum = typeof ScanCustomReportApiModelReportFormatEnum[keyof typeof ScanCustomReportApiModelReportFormatEnum];
/**
 * Check if a given object implements the ScanCustomReportApiModel interface.
 */
export declare function instanceOfScanCustomReportApiModel(value: object): boolean;
export declare function ScanCustomReportApiModelFromJSON(json: any): ScanCustomReportApiModel;
export declare function ScanCustomReportApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanCustomReportApiModel;
export declare function ScanCustomReportApiModelToJSON(value?: ScanCustomReportApiModel | null): any;
