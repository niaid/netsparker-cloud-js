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

import { RequestFile } from './models';

/**
* Represent a filter model of {Netsparker.Cloud.Infrastructure.Models.IssueReportFilterApiModel} type.
*/
export class IssueReportFilterApiModel {
    /**
    * Gets or sets the csv separator.
    */
    'csvSeparator'?: IssueReportFilterApiModel.CsvSeparatorEnum;
    /**
    * Gets or sets the vulnerability\'s severity.
    */
    'severity'?: IssueReportFilterApiModel.SeverityEnum;
    /**
    * Gets or sets the website group\'s name.
    */
    'websiteGroupName'?: string;
    /**
    * Gets or sets the website\'s name.
    */
    'webSiteName'?: string;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "csvSeparator",
            "baseName": "CsvSeparator",
            "type": "IssueReportFilterApiModel.CsvSeparatorEnum"
        },
        {
            "name": "severity",
            "baseName": "Severity",
            "type": "IssueReportFilterApiModel.SeverityEnum"
        },
        {
            "name": "websiteGroupName",
            "baseName": "WebsiteGroupName",
            "type": "string"
        },
        {
            "name": "webSiteName",
            "baseName": "WebSiteName",
            "type": "string"
        }    ];

    static getAttributeTypeMap() {
        return IssueReportFilterApiModel.attributeTypeMap;
    }
}

export namespace IssueReportFilterApiModel {
    export enum CsvSeparatorEnum {
        Comma = <any> 'Comma',
        Semicolon = <any> 'Semicolon',
        Pipe = <any> 'Pipe',
        Tab = <any> 'Tab'
    }
    export enum SeverityEnum {
        BestPractice = <any> 'BestPractice',
        Information = <any> 'Information',
        Low = <any> 'Low',
        Medium = <any> 'Medium',
        High = <any> 'High',
        Critical = <any> 'Critical'
    }
}