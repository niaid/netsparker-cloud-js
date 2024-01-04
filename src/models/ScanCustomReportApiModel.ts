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
export const ScanCustomReportApiModelReportFormatEnum = {
    Xml: 'Xml',
    Csv: 'Csv',
    Pdf: 'Pdf',
    Html: 'Html',
    Txt: 'Txt',
    Json: 'Json'
} as const;
export type ScanCustomReportApiModelReportFormatEnum = typeof ScanCustomReportApiModelReportFormatEnum[keyof typeof ScanCustomReportApiModelReportFormatEnum];


/**
 * Check if a given object implements the ScanCustomReportApiModel interface.
 */
export function instanceOfScanCustomReportApiModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "id" in value;
    isInstance = isInstance && "reportName" in value;

    return isInstance;
}

export function ScanCustomReportApiModelFromJSON(json: any): ScanCustomReportApiModel {
    return ScanCustomReportApiModelFromJSONTyped(json, false);
}

export function ScanCustomReportApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanCustomReportApiModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'excludeIgnoreds': !exists(json, 'ExcludeIgnoreds') ? undefined : json['ExcludeIgnoreds'],
        'id': json['Id'],
        'onlyConfirmedVulnerabilities': !exists(json, 'OnlyConfirmedVulnerabilities') ? undefined : json['OnlyConfirmedVulnerabilities'],
        'onlyUnconfirmedVulnerabilities': !exists(json, 'OnlyUnconfirmedVulnerabilities') ? undefined : json['OnlyUnconfirmedVulnerabilities'],
        'reportName': json['ReportName'],
        'reportFormat': !exists(json, 'ReportFormat') ? undefined : json['ReportFormat'],
    };
}

export function ScanCustomReportApiModelToJSON(value?: ScanCustomReportApiModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'ExcludeIgnoreds': value.excludeIgnoreds,
        'Id': value.id,
        'OnlyConfirmedVulnerabilities': value.onlyConfirmedVulnerabilities,
        'OnlyUnconfirmedVulnerabilities': value.onlyUnconfirmedVulnerabilities,
        'ReportName': value.reportName,
        'ReportFormat': value.reportFormat,
    };
}

