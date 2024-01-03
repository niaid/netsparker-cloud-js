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
 * Represents a model for carrying scan report parameters.
 * @export
 * @interface ScanReportApiModel
 */
export interface ScanReportApiModel {
    /**
     * Gets or sets the content format. This parameter can only be used for vulnerabilities XML and JSON report.
     * @type {string}
     * @memberof ScanReportApiModel
     */
    contentFormat?: ScanReportApiModelContentFormatEnum;
    /**
     * If set to true, HTTP response data will be excluded from the vulnerability detail. This parameter can only be
     * used for vulnerabilities XML report.
     * Default: false
     * @type {boolean}
     * @memberof ScanReportApiModel
     */
    excludeResponseData?: boolean;
    /**
     * Gets or sets the report format.
     * Crawled URLs, scanned URLs and vulnerabilities can be exported as XML, CSV or JSON.
     * Scan detail, SANS Top 25, Owasp Top Ten 2013, WASC Threat Classification, PCI Compliance, HIPAA Compliance, Executive Summary and Knowledge Base reports can be
     * exported as HTML or PDF.
     * ModSecurity WAF Rules report can be exported as TXT.
     * @type {string}
     * @memberof ScanReportApiModel
     */
    format: ScanReportApiModelFormatEnum;
    /**
     * Gets or sets the scan identifier.
     * @type {string}
     * @memberof ScanReportApiModel
     */
    id: string;
    /**
     * Gets or sets the report type.
     * FullScanDetail option corresponds to "Detailed Scan Report (Including addressed issues)".
     * ScanDetail option corresponds to "Detailed Scan Report (Excluding addressed issues)".
     * @type {string}
     * @memberof ScanReportApiModel
     */
    type: ScanReportApiModelTypeEnum;
    /**
     * If this field set true then only the Confirmed Issues will be included to the report results.
     * This option not valid for KnowledgeBase, Crawled, Scanned, ModSecurityWafRules, F5BigIpAsmWafRules report types.
     * Default: null
     * @type {boolean}
     * @memberof ScanReportApiModel
     */
    onlyConfirmedIssues?: boolean;
    /**
     * If this field set true then only the Unconfirmed Issues will be included to the report results.
     * This option not valid for KnowledgeBase, Crawled, Scanned, ModSecurityWafRules, F5BigIpAsmWafRules report types.
     * Default: null
     * @type {boolean}
     * @memberof ScanReportApiModel
     */
    onlyUnconfirmedIssues?: boolean;
    /**
     * If this field set true then the Addressed Issues will be excluded from the report results.
     * FullScanDetail and ScanDetail options override this field.
     * This option not valid for KnowledgeBase, Crawled, Scanned, ModSecurityWafRules, F5BigIpAsmWafRules report types.
     * Default: null
     * @type {boolean}
     * @memberof ScanReportApiModel
     */
    excludeAddressedIssues?: boolean;
    /**
     * If this field set true then the history of issues will be excluded from the report results.
     * If this is unchecked, only the last 10 of the issues history logs will be displayed.
     * This option not valid for KnowledgeBase, Crawled, Scanned, ModSecurityWafRules, F5BigIpAsmWafRules,Vulnerabilities report types.
     * Default: null
     * @type {boolean}
     * @memberof ScanReportApiModel
     */
    excludeHistoryOfIssues?: boolean;
}


/**
 * @export
 */
export const ScanReportApiModelContentFormatEnum = {
    Html: 'Html',
    Markdown: 'Markdown'
} as const;
export type ScanReportApiModelContentFormatEnum = typeof ScanReportApiModelContentFormatEnum[keyof typeof ScanReportApiModelContentFormatEnum];

/**
 * @export
 */
export const ScanReportApiModelFormatEnum = {
    Xml: 'Xml',
    Csv: 'Csv',
    Pdf: 'Pdf',
    Html: 'Html',
    Txt: 'Txt',
    Json: 'Json'
} as const;
export type ScanReportApiModelFormatEnum = typeof ScanReportApiModelFormatEnum[keyof typeof ScanReportApiModelFormatEnum];

/**
 * @export
 */
export const ScanReportApiModelTypeEnum = {
    Crawled: 'Crawled',
    Scanned: 'Scanned',
    Vulnerabilities: 'Vulnerabilities',
    ScanDetail: 'ScanDetail',
    ModSecurityWafRules: 'ModSecurityWafRules',
    OwaspTopTen2013: 'OwaspTopTen2013',
    HipaaCompliance: 'HIPAACompliance',
    Pci32: 'Pci32',
    KnowledgeBase: 'KnowledgeBase',
    ExecutiveSummary: 'ExecutiveSummary',
    FullScanDetail: 'FullScanDetail',
    OwaspTopTen2017: 'OwaspTopTen2017',
    CustomReport: 'CustomReport',
    Iso27001Compliance: 'Iso27001Compliance',
    F5BigIpAsmWafRules: 'F5BigIpAsmWafRules',
    Wasc: 'WASC',
    SansTop25: 'SansTop25',
    Asvs40: 'Asvs40',
    Nistsp80053: 'Nistsp80053',
    DisaStig: 'DisaStig',
    OwaspApiTop10: 'OwaspApiTop10',
    OwaspTopTen2021: 'OwaspTopTen2021',
    VulnerabilitiesPerWebsite: 'VulnerabilitiesPerWebsite',
    OwaspApiTopTen2023: 'OwaspApiTopTen2023',
    PciDss40: 'PciDss40'
} as const;
export type ScanReportApiModelTypeEnum = typeof ScanReportApiModelTypeEnum[keyof typeof ScanReportApiModelTypeEnum];


/**
 * Check if a given object implements the ScanReportApiModel interface.
 */
export function instanceOfScanReportApiModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "format" in value;
    isInstance = isInstance && "id" in value;
    isInstance = isInstance && "type" in value;

    return isInstance;
}

export function ScanReportApiModelFromJSON(json: any): ScanReportApiModel {
    return ScanReportApiModelFromJSONTyped(json, false);
}

export function ScanReportApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanReportApiModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'contentFormat': !exists(json, 'ContentFormat') ? undefined : json['ContentFormat'],
        'excludeResponseData': !exists(json, 'ExcludeResponseData') ? undefined : json['ExcludeResponseData'],
        'format': json['Format'],
        'id': json['Id'],
        'type': json['Type'],
        'onlyConfirmedIssues': !exists(json, 'OnlyConfirmedIssues') ? undefined : json['OnlyConfirmedIssues'],
        'onlyUnconfirmedIssues': !exists(json, 'OnlyUnconfirmedIssues') ? undefined : json['OnlyUnconfirmedIssues'],
        'excludeAddressedIssues': !exists(json, 'ExcludeAddressedIssues') ? undefined : json['ExcludeAddressedIssues'],
        'excludeHistoryOfIssues': !exists(json, 'ExcludeHistoryOfIssues') ? undefined : json['ExcludeHistoryOfIssues'],
    };
}

export function ScanReportApiModelToJSON(value?: ScanReportApiModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'ContentFormat': value.contentFormat,
        'ExcludeResponseData': value.excludeResponseData,
        'Format': value.format,
        'Id': value.id,
        'Type': value.type,
        'OnlyConfirmedIssues': value.onlyConfirmedIssues,
        'OnlyUnconfirmedIssues': value.onlyUnconfirmedIssues,
        'ExcludeAddressedIssues': value.excludeAddressedIssues,
        'ExcludeHistoryOfIssues': value.excludeHistoryOfIssues,
    };
}
