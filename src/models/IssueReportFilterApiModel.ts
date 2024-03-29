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
 * Represent a filter model of {Netsparker.Cloud.Infrastructure.Models.IssueReportFilterApiModel} type.
 * @export
 * @interface IssueReportFilterApiModel
 */
export interface IssueReportFilterApiModel {
    /**
     * This sets the query parameter for the CSV separator. The options are Comma, Semicolon, Pipe, and Tab.
     * @type {string}
     * @memberof IssueReportFilterApiModel
     */
    csvSeparator?: IssueReportFilterApiModelCsvSeparatorEnum;
    /**
     * This sets the query parameter for the vulnerability severity level. The options are Critical, High, Medium, Low, Information, and Best Practice.
     * @type {string}
     * @memberof IssueReportFilterApiModel
     */
    severity?: IssueReportFilterApiModelSeverityEnum;
    /**
     * This sets the query parameter for a website group's name that you entered while creating the website group in Invicti.
     * @type {string}
     * @memberof IssueReportFilterApiModel
     */
    websiteGroupName?: string;
    /**
     * This sets the query parameter for a website's name that you entered while adding the website to Invicti.
     * @type {string}
     * @memberof IssueReportFilterApiModel
     */
    webSiteName?: string;
    /**
     * This sets the query parameter for the start date on issues to be reported. For example, if you set 02/10/2022, this is the start date for Invicti to generate the issue report. You can use the date format defined in your account. Go to netsparkercloud.com/account/changesettings to view the current format. For example, the date and time format can be 02/06/23 (MM/dd/yy) 00:00:00.
     * @type {Date}
     * @memberof IssueReportFilterApiModel
     */
    startDate?: Date;
    /**
     * This sets the query parameter for the end date on issues to be reported. For example, if you set 02/18/2023, this is the end date for Invicti to generate the report. Invicti generates a report of all issues until the specified date. You can use the date format defined in your account. Go to netsparkercloud.com/account/changesettings to view the current format. For example, the date and time format can be 02/06/23 (MM/dd/yy) 00:00:00.
     * @type {Date}
     * @memberof IssueReportFilterApiModel
     */
    endDate?: Date;
}


/**
 * @export
 */
export const IssueReportFilterApiModelCsvSeparatorEnum = {
    Comma: 'Comma',
    Semicolon: 'Semicolon',
    Pipe: 'Pipe',
    Tab: 'Tab'
} as const;
export type IssueReportFilterApiModelCsvSeparatorEnum = typeof IssueReportFilterApiModelCsvSeparatorEnum[keyof typeof IssueReportFilterApiModelCsvSeparatorEnum];

/**
 * @export
 */
export const IssueReportFilterApiModelSeverityEnum = {
    BestPractice: 'BestPractice',
    Information: 'Information',
    Low: 'Low',
    Medium: 'Medium',
    High: 'High',
    Critical: 'Critical'
} as const;
export type IssueReportFilterApiModelSeverityEnum = typeof IssueReportFilterApiModelSeverityEnum[keyof typeof IssueReportFilterApiModelSeverityEnum];


/**
 * Check if a given object implements the IssueReportFilterApiModel interface.
 */
export function instanceOfIssueReportFilterApiModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function IssueReportFilterApiModelFromJSON(json: any): IssueReportFilterApiModel {
    return IssueReportFilterApiModelFromJSONTyped(json, false);
}

export function IssueReportFilterApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): IssueReportFilterApiModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'csvSeparator': !exists(json, 'CsvSeparator') ? undefined : json['CsvSeparator'],
        'severity': !exists(json, 'Severity') ? undefined : json['Severity'],
        'websiteGroupName': !exists(json, 'WebsiteGroupName') ? undefined : json['WebsiteGroupName'],
        'webSiteName': !exists(json, 'WebSiteName') ? undefined : json['WebSiteName'],
        'startDate': !exists(json, 'StartDate') ? undefined : (new Date(json['StartDate'])),
        'endDate': !exists(json, 'EndDate') ? undefined : (new Date(json['EndDate'])),
    };
}

export function IssueReportFilterApiModelToJSON(value?: IssueReportFilterApiModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'CsvSeparator': value.csvSeparator,
        'Severity': value.severity,
        'WebsiteGroupName': value.websiteGroupName,
        'WebSiteName': value.webSiteName,
        'StartDate': value.startDate === undefined ? undefined : (value.startDate.toISOString()),
        'EndDate': value.endDate === undefined ? undefined : (value.endDate.toISOString()),
    };
}

