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
/// <reference types="node" />
import http from 'http';
import { ApiScanStatusModel } from '../model/apiScanStatusModel';
import { AuthVerificationApiResult } from '../model/authVerificationApiResult';
import { BaseScanApiModel } from '../model/baseScanApiModel';
import { FormAuthenticationVerificationApiModel } from '../model/formAuthenticationVerificationApiModel';
import { IncrementalApiModel } from '../model/incrementalApiModel';
import { NewGroupScanApiModel } from '../model/newGroupScanApiModel';
import { NewScanTaskApiModel } from '../model/newScanTaskApiModel';
import { NewScanTaskWithProfileApiModel } from '../model/newScanTaskWithProfileApiModel';
import { NewScheduledIncrementalScanApiModel } from '../model/newScheduledIncrementalScanApiModel';
import { NewScheduledScanApiModel } from '../model/newScheduledScanApiModel';
import { NewScheduledWithProfileApiModel } from '../model/newScheduledWithProfileApiModel';
import { ScanTaskListApiResult } from '../model/scanTaskListApiResult';
import { ScanTaskModel } from '../model/scanTaskModel';
import { ScheduledScanListApiResult } from '../model/scheduledScanListApiResult';
import { TestScanProfileCredentialsRequestModel } from '../model/testScanProfileCredentialsRequestModel';
import { UpdateScheduledIncrementalScanApiModel } from '../model/updateScheduledIncrementalScanApiModel';
import { UpdateScheduledScanApiModel } from '../model/updateScheduledScanApiModel';
import { UpdateScheduledScanModel } from '../model/updateScheduledScanModel';
import { VulnerabilityModel } from '../model/vulnerabilityModel';
import { Authentication, Interceptor } from '../model/models';
export declare enum ScansApiApiKeys {
}
export declare class ScansApi {
    protected _basePath: string;
    protected _defaultHeaders: any;
    protected _useQuerystring: boolean;
    protected authentications: {
        default: Authentication;
    };
    protected interceptors: Interceptor[];
    constructor(basePath?: string);
    set useQuerystring(value: boolean);
    set basePath(basePath: string);
    set defaultHeaders(defaultHeaders: any);
    get defaultHeaders(): any;
    get basePath(): string;
    setDefaultAuthentication(auth: Authentication): void;
    setApiKey(key: ScansApiApiKeys, value: string): void;
    addInterceptor(interceptor: Interceptor): void;
    /**
     *
     * @summary Stops a scan in progress.
     * @param id The identifier of scan.
     */
    scansCancel(id: string, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: string;
    }>;
    /**
     *
     * @summary Returns the custom report of a scan in the specified format.
     * @param id Gets or sets the scan identifier.
     * @param reportName Gets or sets report name. Report name also keeps report type in it.
     * @param excludeIgnoreds If set to true, HTTP response data will be excluded from the report results. This parameter can only be  used for vulnerabilities XML report.  Default: false
     * @param onlyConfirmedVulnerabilities If set to true, HTTP response data will be included only confirmed vulnerabilities to report results. This  parameter can only be  used for vulnerabilities reports.  Default: false
     * @param onlyUnconfirmedVulnerabilities If set to true, HTTP response data will be included only unconfirmed vulnerabilities to report results. This  parameter can only be  used for vulnerabilities reports.  Default: false
     * @param reportFormat Gets or sets the report format.
     */
    scansCustomReport(id: string, reportName: string, excludeIgnoreds?: boolean, onlyConfirmedVulnerabilities?: boolean, onlyUnconfirmedVulnerabilities?: boolean, reportFormat?: 'Xml' | 'Csv' | 'Pdf' | 'Html' | 'Txt' | 'Json', options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body?: any;
    }>;
    /**
     *
     * @summary Deletes scan data.
     * @param ids The identifiers of scans.
     */
    scansDelete(ids: Array<string>, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: string;
    }>;
    /**
     *
     * @summary Gets the detail of a scan.
     * @param id The identifier of scan.
     */
    scansDetail(id: string, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: ScanTaskModel;
    }>;
    /**
     *
     * @summary Downloads the scan file as zip
     * @param scanId The scan id
     */
    scansDownloadScanFile(scanId: string, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: object;
    }>;
    /**
     *
     * @summary Launches an incremental scan based on the provided base scan identifier.
     * @param model Contains data that is required to create an incremental scan. Base scan should be in completed  state. Currently running or cancelled scans are not valid.
     */
    scansIncremental(model: IncrementalApiModel, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: ScanTaskModel;
    }>;
    /**
     *
     * @summary Gets the list of scans and their details.
     * @param page The page index.
     * @param pageSize The page size. Page size can be any value between 1 and 200.
     */
    scansList(page?: number, pageSize?: number, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: ScanTaskListApiResult;
    }>;
    /**
     *
     * @summary Gets the list of scans by state
     * @param scanTaskState The state of ScanTask.
     * @param targetUrlCriteria Enter the search criteria that contains the Target URL of scan
     * @param page The page index.
     * @param pageSize The page size. Page size can be any value between 1 and 200.
     * @param startDate The start date is used for scan StateChanged field and it is less than or equal to StateChanged field.              If scanTask field set as Queued, the start date is used for scan Initiated field.Format: MM/dd/yyyy 00:00:00
     * @param endDate The end date is used for scan StateChanged field and it is greater than or equal to StateChanged field.              If scanTask field set as Queued, the end date is used for scan Initiated field.Format: MM/dd/yyyy 23:59:59
     */
    scansListByState(scanTaskState: 'Queued' | 'Scanning' | 'Archiving' | 'Complete' | 'Failed' | 'Cancelled' | 'Delayed' | 'Pausing' | 'Paused' | 'Resuming', targetUrlCriteria?: string, page?: number, pageSize?: number, startDate?: Date, endDate?: Date, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: ScanTaskListApiResult;
    }>;
    /**
     *
     * @summary Gets the list of scans by stateChanged
     * @param startDate The start date is used for scan StateChanged field and it is less than or equal to StateChanged field. Format: MM/dd/yyyy 00:00:00
     * @param endDate The end date is used for scan StateChanged field and it is greater than or equal to StateChanged field. Format : MM/dd/yyyy 23:59:59
     * @param page The page index.
     * @param pageSize The page size. Page size can be any value between 1 and 200.
     */
    scansListByStateChanged(startDate: Date, endDate: Date, page?: number, pageSize?: number, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: ScanTaskListApiResult;
    }>;
    /**
     *
     * @summary Gets the list of scans and their details.
     * @param websiteUrl The website URL.
     * @param targetUrl The target URL of the scan.
     * @param page The page index.
     * @param pageSize The page size. Page size can be any value between 1 and 200.
     * @param initiatedDateSortType The initiated date sort type.
     */
    scansListByWebsite(websiteUrl?: string, targetUrl?: string, page?: number, pageSize?: number, initiatedDateSortType?: 'Ascending' | 'Descending', options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: ScanTaskListApiResult;
    }>;
    /**
     *
     * @summary Gets the list of scheduled scans which are scheduled to be launched in the future.
     * @param page The page index.
     * @param pageSize The page size. Page size can be any value between 1 and 200.
     */
    scansListScheduled(page?: number, pageSize?: number, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: ScheduledScanListApiResult;
    }>;
    /**
     *
     * @summary Launches a new scan.
     * @param model Contains data that is required to create a new scan.
     */
    scansNew(model: NewScanTaskApiModel, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: Array<ScanTaskModel>;
    }>;
    /**
     *
     * @summary Launches a new scan with same configuration from the scan specified with scan id.
     * @param id The identifier of scan.
     */
    scansNewFromScan(id: string, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: ScanTaskModel;
    }>;
    /**
     *
     * @summary Launches a new group scan.
     * @param model Contains data that is required to create a new group scan.
     */
    scansNewGroupScan(model: NewGroupScanApiModel, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: Array<ScanTaskModel>;
    }>;
    /**
     *
     * @summary Launches a new scan with profile id.
     * @param model Contains data that is required to create a new scan.
     */
    scansNewWithProfile(model: NewScanTaskWithProfileApiModel, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: ScanTaskModel;
    }>;
    /**
     *
     * @summary Pauses a scan in progress.
     * @param id The identifier of scan.
     */
    scansPause(id: string, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: string;
    }>;
    /**
     *
     * @summary Returns the report of a scan in the specified format.
     * @param format Gets or sets the report format.  Crawled URLs, scanned URLs and vulnerabilities can be exported as XML, CSV or JSON.  Scan detail, SANS Top 25, Owasp Top Ten 2013, WASC Threat Classification, PCI Compliance, HIPAA Compliance, Executive Summary and Knowledge Base reports can be  exported as HTML or PDF.  ModSecurity WAF Rules report can be exported as TXT.
     * @param id Gets or sets the scan identifier.
     * @param type Gets or sets the report type.  FullScanDetail option corresponds to \&quot;Detailed Scan Report (Including addressed issues)\&quot;.  ScanDetail option corresponds to \&quot;Detailed Scan Report (Excluding addressed issues)\&quot;.
     * @param contentFormat Gets or sets the content format. This parameter can only be used for vulnerabilities XML and JSON report.
     * @param excludeResponseData If set to true, HTTP response data will be excluded from the vulnerability detail. This parameter can only be  used for vulnerabilities XML report.  Default: false
     * @param onlyConfirmedIssues If this field set true then only the Confirmed Issues will be included to the report results.  This option not valid for KnowledgeBase, Crawled, Scanned, ModSecurityWafRules, F5BigIpAsmWafRules report types.  Default: null
     * @param onlyUnconfirmedIssues If this field set true then only the Unconfirmed Issues will be included to the report results.  This option not valid for KnowledgeBase, Crawled, Scanned, ModSecurityWafRules, F5BigIpAsmWafRules report types.  Default: null
     * @param excludeAddressedIssues If this field set true then the Addressed Issues will be excluded from the report results.  FullScanDetail and ScanDetail options override this field.  This option not valid for KnowledgeBase, Crawled, Scanned, ModSecurityWafRules, F5BigIpAsmWafRules report types.  Default: null
     */
    scansReport(format: 'Xml' | 'Csv' | 'Pdf' | 'Html' | 'Txt' | 'Json', id: string, type: 'Crawled' | 'Scanned' | 'Vulnerabilities' | 'ScanDetail' | 'ModSecurityWafRules' | 'OwaspTopTen2013' | 'HIPAACompliance' | 'PCICompliance' | 'KnowledgeBase' | 'ExecutiveSummary' | 'FullScanDetail' | 'OwaspTopTen2017' | 'CustomReport' | 'Iso27001Compliance' | 'F5BigIpAsmWafRules' | 'WASC' | 'SansTop25', contentFormat?: 'Html' | 'Markdown', excludeResponseData?: boolean, onlyConfirmedIssues?: boolean, onlyUnconfirmedIssues?: boolean, excludeAddressedIssues?: boolean, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body?: any;
    }>;
    /**
     *
     * @summary Gets the result of a scan.
     * @param id The identifier of scan.
     */
    scansResult(id: string, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: Array<VulnerabilityModel>;
    }>;
    /**
     *
     * @summary Resumes a paused scan.
     * @param id The identifier of scan.
     */
    scansResume(id: string, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: string;
    }>;
    /**
     *
     * @summary Launches a retest scan based on the provided base scan identifier.
     * @param model Contains data that is required to create a retest scan. Base scan should be in completed state.  Currently running or cancelled scans are not valid.
     */
    scansRetest(model: BaseScanApiModel, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: ScanTaskModel;
    }>;
    /**
     *
     * @summary Schedules a scan to be launched in the future.
     * @param model Contains data that required to create a scheduled scan.
     */
    scansSchedule(model: NewScheduledScanApiModel, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: UpdateScheduledScanModel;
    }>;
    /**
     *
     * @summary Schedules an incremental scan to be launched in the future.
     * @param model Contains data that required to create a scheduled scan.
     */
    scansScheduleIncremental(model: NewScheduledIncrementalScanApiModel, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: UpdateScheduledScanModel;
    }>;
    /**
     *
     * @summary Schedules a scan by a profile to be launched in the future.
     * @param model Contains profile and scheduling data
     */
    scansScheduleWithProfile(model: NewScheduledWithProfileApiModel, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: UpdateScheduledScanModel;
    }>;
    /**
     *
     * @summary Gets the status of a scan.
     * @param id The identifier of scan.
     */
    scansStatus(id: string, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: ApiScanStatusModel;
    }>;
    /**
     *
     * @summary Tests the credentials of scan profile for specific url.
     * @param model Scan model.
     */
    scansTestScanProfileCredentials(model: TestScanProfileCredentialsRequestModel, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: TestScanProfileCredentialsRequestModel;
    }>;
    /**
     *
     * @summary Removes a scheduled scan.
     * @param id The identifier of scan.
     */
    scansUnschedule(id: string, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body?: any;
    }>;
    /**
     *
     * @summary Updates a scheduled scan.
     * @param model Contains data that is required to update a scheduled scan.
     */
    scansUpdateScheduled(model: UpdateScheduledScanApiModel, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: UpdateScheduledScanApiModel;
    }>;
    /**
     *
     * @summary Updates an incremental scheduled scan.
     * @param model Contains data that is required to update a scheduled scan.
     */
    scansUpdateScheduledIncremental(model: UpdateScheduledIncrementalScanApiModel, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: UpdateScheduledIncrementalScanApiModel;
    }>;
    /**
     *
     * @summary Verifies the specified form authentication settings.
     * @param model Contains form authentication settings.
     */
    scansVerifyFormAuth(model: FormAuthenticationVerificationApiModel, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: AuthVerificationApiResult;
    }>;
}
