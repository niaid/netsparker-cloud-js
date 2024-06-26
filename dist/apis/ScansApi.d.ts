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
import * as runtime from '../runtime';
import type { ApiScanStatusModel, AuthVerificationApiResult, BaseScanApiModel, FormAuthenticationVerificationApiModel, IncrementalApiModel, NewGroupScanApiModel, NewScanTaskApiModel, NewScanTaskWithProfileApiModel, NewScheduledIncrementalScanApiModel, NewScheduledScanApiModel, NewScheduledWithProfileApiModel, ScanTaskListApiResult, ScanTaskModel, ScansValidateImportedLinksFileReq, ScheduledScanListApiResult, TestScanProfileCredentialsRequestModel, UpdateScheduledIncrementalScanApiModel, UpdateScheduledScanApiModel, UpdateScheduledScanModel, VulnerabilityModel } from '../models/index';
export interface ScansCancelRequest {
    id: string;
}
export interface ScansCustomReportRequest {
    id: string;
    reportName: string;
    excludeIgnoreds?: boolean;
    onlyConfirmedVulnerabilities?: boolean;
    onlyUnconfirmedVulnerabilities?: boolean;
    reportFormat?: ScansCustomReportReportFormatEnum;
}
export interface ScansDeleteRequest {
    ids: Array<string>;
}
export interface ScansDetailRequest {
    id: string;
}
export interface ScansDownloadPciScanReportRequest {
    scanId: string;
    reportType: ScansDownloadPciScanReportReportTypeEnum;
}
export interface ScansDownloadScanFileRequest {
    scanId: string;
    isWindowsCompatible?: boolean;
}
export interface ScansDownloadScanFileCheckRequest {
    scanId: string;
}
export interface ScansIncrementalRequest {
    model: IncrementalApiModel;
}
export interface ScansListRequest {
    page?: number;
    pageSize?: number;
}
export interface ScansListByStateRequest {
    scanTaskState: ScansListByStateScanTaskStateEnum;
    targetUrlCriteria?: string;
    page?: number;
    pageSize?: number;
    startDate?: Date;
    endDate?: Date;
}
export interface ScansListByStateChangedRequest {
    startDate: Date;
    endDate: Date;
    page?: number;
    pageSize?: number;
}
export interface ScansListByWebsiteRequest {
    websiteUrl?: string;
    targetUrl?: string;
    page?: number;
    pageSize?: number;
    initiatedDateSortType?: ScansListByWebsiteInitiatedDateSortTypeEnum;
}
export interface ScansListScheduledRequest {
    page?: number;
    pageSize?: number;
}
export interface ScansNewRequest {
    model: Omit<NewScanTaskApiModel, 'IsTargetUrlRequired'>;
}
export interface ScansNewFromScanRequest {
    id: string;
}
export interface ScansNewGroupScanRequest {
    model: NewGroupScanApiModel;
}
export interface ScansNewWithProfileRequest {
    model: NewScanTaskWithProfileApiModel;
}
export interface ScansPauseRequest {
    id: string;
}
export interface ScansReportRequest {
    format: ScansReportFormatEnum;
    id: string;
    type: ScansReportTypeEnum;
    contentFormat?: ScansReportContentFormatEnum;
    excludeResponseData?: boolean;
    onlyConfirmedIssues?: boolean;
    onlyUnconfirmedIssues?: boolean;
    excludeAddressedIssues?: boolean;
    excludeHistoryOfIssues?: boolean;
}
export interface ScansResultRequest {
    id: string;
}
export interface ScansResumeRequest {
    id: string;
}
export interface ScansRetestRequest {
    model: BaseScanApiModel;
}
export interface ScansScheduleRequest {
    model: Omit<NewScheduledScanApiModel, 'IsTargetUrlRequired'>;
}
export interface ScansScheduleIncrementalRequest {
    model: NewScheduledIncrementalScanApiModel;
}
export interface ScansScheduleWithProfileRequest {
    model: NewScheduledWithProfileApiModel;
}
export interface ScansStatusRequest {
    id: string;
}
export interface ScansTestScanProfileCredentialsRequest {
    model: TestScanProfileCredentialsRequestModel;
}
export interface ScansUnscheduleRequest {
    id: string;
}
export interface ScansUpdateScheduledRequest {
    model: Omit<UpdateScheduledScanApiModel, 'IsTargetUrlRequired'>;
}
export interface ScansUpdateScheduledIncrementalRequest {
    model: UpdateScheduledIncrementalScanApiModel;
}
export interface ScansValidateImportedLinksFileRequest {
    siteUrl: string;
    scansValidateImportedLinksFileReq: ScansValidateImportedLinksFileReq;
    importType?: ScansValidateImportedLinksFileImportTypeEnum;
}
export interface ScansVerifyFormAuthRequest {
    model: FormAuthenticationVerificationApiModel;
}
/**
 *
 */
export declare class ScansApi extends runtime.BaseAPI {
    /**
     * Stops a scan in progress.
     */
    scansCancelRaw(requestParameters: ScansCancelRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>>;
    /**
     * Stops a scan in progress.
     */
    scansCancel(requestParameters: ScansCancelRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string>;
    /**
     * Returns the custom report of a scan in the specified format.
     */
    scansCustomReportRaw(requestParameters: ScansCustomReportRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>>;
    /**
     * Returns the custom report of a scan in the specified format.
     */
    scansCustomReport(requestParameters: ScansCustomReportRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void>;
    /**
     * Deletes scan data.
     */
    scansDeleteRaw(requestParameters: ScansDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>>;
    /**
     * Deletes scan data.
     */
    scansDelete(requestParameters: ScansDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string>;
    /**
     * Gets the detail of a scan.
     */
    scansDetailRaw(requestParameters: ScansDetailRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanTaskModel>>;
    /**
     * Gets the detail of a scan.
     */
    scansDetail(requestParameters: ScansDetailRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanTaskModel>;
    /**
     * Downloads the pci scan report based on report type
     */
    scansDownloadPciScanReportRaw(requestParameters: ScansDownloadPciScanReportRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<Blob>>;
    /**
     * Downloads the pci scan report based on report type
     */
    scansDownloadPciScanReport(requestParameters: ScansDownloadPciScanReportRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<Blob>;
    /**
     * Downloads the scan file as zip
     */
    scansDownloadScanFileRaw(requestParameters: ScansDownloadScanFileRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<Blob>>;
    /**
     * Downloads the scan file as zip
     */
    scansDownloadScanFile(requestParameters: ScansDownloadScanFileRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<Blob>;
    /**
     * Downloads the scan file as zip
     */
    scansDownloadScanFileCheckRaw(requestParameters: ScansDownloadScanFileCheckRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>>;
    /**
     * Downloads the scan file as zip
     */
    scansDownloadScanFileCheck(requestParameters: ScansDownloadScanFileCheckRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object>;
    /**
     * Launches an incremental scan based on the provided base scan identifier.
     */
    scansIncrementalRaw(requestParameters: ScansIncrementalRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanTaskModel>>;
    /**
     * Launches an incremental scan based on the provided base scan identifier.
     */
    scansIncremental(requestParameters: ScansIncrementalRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanTaskModel>;
    /**
     * Gets the list of scans and their details.
     */
    scansListRaw(requestParameters: ScansListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanTaskListApiResult>>;
    /**
     * Gets the list of scans and their details.
     */
    scansList(requestParameters?: ScansListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanTaskListApiResult>;
    /**
     * Gets the list of scans by state
     */
    scansListByStateRaw(requestParameters: ScansListByStateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanTaskListApiResult>>;
    /**
     * Gets the list of scans by state
     */
    scansListByState(requestParameters: ScansListByStateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanTaskListApiResult>;
    /**
     * Gets the list of scans by stateChanged
     */
    scansListByStateChangedRaw(requestParameters: ScansListByStateChangedRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanTaskListApiResult>>;
    /**
     * Gets the list of scans by stateChanged
     */
    scansListByStateChanged(requestParameters: ScansListByStateChangedRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanTaskListApiResult>;
    /**
     * Gets the list of scans and their details.
     */
    scansListByWebsiteRaw(requestParameters: ScansListByWebsiteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanTaskListApiResult>>;
    /**
     * Gets the list of scans and their details.
     */
    scansListByWebsite(requestParameters?: ScansListByWebsiteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanTaskListApiResult>;
    /**
     * Gets the list of scheduled scans which are scheduled to be launched in the future.
     */
    scansListScheduledRaw(requestParameters: ScansListScheduledRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScheduledScanListApiResult>>;
    /**
     * Gets the list of scheduled scans which are scheduled to be launched in the future.
     */
    scansListScheduled(requestParameters?: ScansListScheduledRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScheduledScanListApiResult>;
    /**
     * Launches a new scan.
     */
    scansNewRaw(requestParameters: ScansNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<Array<ScanTaskModel>>>;
    /**
     * Launches a new scan.
     */
    scansNew(requestParameters: ScansNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<Array<ScanTaskModel>>;
    /**
     * Launches a new scan with same configuration from the scan specified with scan id.
     */
    scansNewFromScanRaw(requestParameters: ScansNewFromScanRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanTaskModel>>;
    /**
     * Launches a new scan with same configuration from the scan specified with scan id.
     */
    scansNewFromScan(requestParameters: ScansNewFromScanRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanTaskModel>;
    /**
     * Launches a new group scan.
     */
    scansNewGroupScanRaw(requestParameters: ScansNewGroupScanRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<Array<ScanTaskModel>>>;
    /**
     * Launches a new group scan.
     */
    scansNewGroupScan(requestParameters: ScansNewGroupScanRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<Array<ScanTaskModel>>;
    /**
     * Launches a new scan with profile id.
     */
    scansNewWithProfileRaw(requestParameters: ScansNewWithProfileRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanTaskModel>>;
    /**
     * Launches a new scan with profile id.
     */
    scansNewWithProfile(requestParameters: ScansNewWithProfileRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanTaskModel>;
    /**
     * Pauses a scan in progress.
     */
    scansPauseRaw(requestParameters: ScansPauseRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>>;
    /**
     * Pauses a scan in progress.
     */
    scansPause(requestParameters: ScansPauseRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string>;
    /**
     * Pausing scans in Scanning status.
     */
    scansPauseActiveScansRaw(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>>;
    /**
     * Pausing scans in Scanning status.
     */
    scansPauseActiveScans(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object>;
    /**
     * Returns the report of a scan in the specified format.
     */
    scansReportRaw(requestParameters: ScansReportRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<Blob>>;
    /**
     * Returns the report of a scan in the specified format.
     */
    scansReport(requestParameters: ScansReportRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<Blob>;
    /**
     * Gets the result of a scan.
     */
    scansResultRaw(requestParameters: ScansResultRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<Array<VulnerabilityModel>>>;
    /**
     * Gets the result of a scan.
     */
    scansResult(requestParameters: ScansResultRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<Array<VulnerabilityModel>>;
    /**
     * Resumes a paused scan.
     */
    scansResumeRaw(requestParameters: ScansResumeRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>>;
    /**
     * Resumes a paused scan.
     */
    scansResume(requestParameters: ScansResumeRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string>;
    /**
     * Resuming \"Paused scans\" with the Pause active scan endpoint.
     */
    scansResumePausedScansRaw(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>>;
    /**
     * Resuming \"Paused scans\" with the Pause active scan endpoint.
     */
    scansResumePausedScans(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object>;
    /**
     * Launches a retest scan based on the provided base scan identifier.
     */
    scansRetestRaw(requestParameters: ScansRetestRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanTaskModel>>;
    /**
     * Launches a retest scan based on the provided base scan identifier.
     */
    scansRetest(requestParameters: ScansRetestRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanTaskModel>;
    /**
     * Schedules a scan to be launched in the future.
     */
    scansScheduleRaw(requestParameters: ScansScheduleRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<UpdateScheduledScanModel>>;
    /**
     * Schedules a scan to be launched in the future.
     */
    scansSchedule(requestParameters: ScansScheduleRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<UpdateScheduledScanModel>;
    /**
     * Schedules an incremental scan to be launched in the future.
     */
    scansScheduleIncrementalRaw(requestParameters: ScansScheduleIncrementalRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<UpdateScheduledScanModel>>;
    /**
     * Schedules an incremental scan to be launched in the future.
     */
    scansScheduleIncremental(requestParameters: ScansScheduleIncrementalRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<UpdateScheduledScanModel>;
    /**
     * Schedules a scan by a profile to be launched in the future.
     */
    scansScheduleWithProfileRaw(requestParameters: ScansScheduleWithProfileRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<UpdateScheduledScanModel>>;
    /**
     * Schedules a scan by a profile to be launched in the future.
     */
    scansScheduleWithProfile(requestParameters: ScansScheduleWithProfileRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<UpdateScheduledScanModel>;
    /**
     * Gets the status of a scan.
     */
    scansStatusRaw(requestParameters: ScansStatusRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ApiScanStatusModel>>;
    /**
     * Gets the status of a scan.
     */
    scansStatus(requestParameters: ScansStatusRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ApiScanStatusModel>;
    /**
     * Tests the credentials of scan profile for specific url.
     */
    scansTestScanProfileCredentialsRaw(requestParameters: ScansTestScanProfileCredentialsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<TestScanProfileCredentialsRequestModel>>;
    /**
     * Tests the credentials of scan profile for specific url.
     */
    scansTestScanProfileCredentials(requestParameters: ScansTestScanProfileCredentialsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<TestScanProfileCredentialsRequestModel>;
    /**
     * Removes and deletes a scheduled scan.
     */
    scansUnscheduleRaw(requestParameters: ScansUnscheduleRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>>;
    /**
     * Removes and deletes a scheduled scan.
     */
    scansUnschedule(requestParameters: ScansUnscheduleRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void>;
    /**
     * Updates a scheduled scan.
     */
    scansUpdateScheduledRaw(requestParameters: ScansUpdateScheduledRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<UpdateScheduledScanApiModel>>;
    /**
     * Updates a scheduled scan.
     */
    scansUpdateScheduled(requestParameters: ScansUpdateScheduledRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<UpdateScheduledScanApiModel>;
    /**
     * Updates an incremental scheduled scan.
     */
    scansUpdateScheduledIncrementalRaw(requestParameters: ScansUpdateScheduledIncrementalRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<UpdateScheduledIncrementalScanApiModel>>;
    /**
     * Updates an incremental scheduled scan.
     */
    scansUpdateScheduledIncremental(requestParameters: ScansUpdateScheduledIncrementalRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<UpdateScheduledIncrementalScanApiModel>;
    /**
     */
    scansValidateImportedLinksFileRaw(requestParameters: ScansValidateImportedLinksFileRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>>;
    /**
     */
    scansValidateImportedLinksFile(requestParameters: ScansValidateImportedLinksFileRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object>;
    /**
     * Verifies the specified form authentication settings.
     */
    scansVerifyFormAuthRaw(requestParameters: ScansVerifyFormAuthRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<AuthVerificationApiResult>>;
    /**
     * Verifies the specified form authentication settings.
     */
    scansVerifyFormAuth(requestParameters: ScansVerifyFormAuthRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<AuthVerificationApiResult>;
}
/**
 * @export
 */
export declare const ScansCustomReportReportFormatEnum: {
    readonly Xml: "Xml";
    readonly Csv: "Csv";
    readonly Pdf: "Pdf";
    readonly Html: "Html";
    readonly Txt: "Txt";
    readonly Json: "Json";
};
export type ScansCustomReportReportFormatEnum = typeof ScansCustomReportReportFormatEnum[keyof typeof ScansCustomReportReportFormatEnum];
/**
 * @export
 */
export declare const ScansDownloadPciScanReportReportTypeEnum: {
    readonly Attestation: "Attestation";
    readonly Detailed: "Detailed";
    readonly Executive: "Executive";
};
export type ScansDownloadPciScanReportReportTypeEnum = typeof ScansDownloadPciScanReportReportTypeEnum[keyof typeof ScansDownloadPciScanReportReportTypeEnum];
/**
 * @export
 */
export declare const ScansListByStateScanTaskStateEnum: {
    readonly Queued: "Queued";
    readonly Scanning: "Scanning";
    readonly Archiving: "Archiving";
    readonly Complete: "Complete";
    readonly Failed: "Failed";
    readonly Cancelled: "Cancelled";
    readonly Delayed: "Delayed";
    readonly Pausing: "Pausing";
    readonly Paused: "Paused";
    readonly Resuming: "Resuming";
    readonly AsyncArchiving: "AsyncArchiving";
};
export type ScansListByStateScanTaskStateEnum = typeof ScansListByStateScanTaskStateEnum[keyof typeof ScansListByStateScanTaskStateEnum];
/**
 * @export
 */
export declare const ScansListByWebsiteInitiatedDateSortTypeEnum: {
    readonly Ascending: "Ascending";
    readonly Descending: "Descending";
};
export type ScansListByWebsiteInitiatedDateSortTypeEnum = typeof ScansListByWebsiteInitiatedDateSortTypeEnum[keyof typeof ScansListByWebsiteInitiatedDateSortTypeEnum];
/**
 * @export
 */
export declare const ScansReportFormatEnum: {
    readonly Xml: "Xml";
    readonly Csv: "Csv";
    readonly Pdf: "Pdf";
    readonly Html: "Html";
    readonly Txt: "Txt";
    readonly Json: "Json";
};
export type ScansReportFormatEnum = typeof ScansReportFormatEnum[keyof typeof ScansReportFormatEnum];
/**
 * @export
 */
export declare const ScansReportTypeEnum: {
    readonly Crawled: "Crawled";
    readonly Scanned: "Scanned";
    readonly Vulnerabilities: "Vulnerabilities";
    readonly ScanDetail: "ScanDetail";
    readonly ModSecurityWafRules: "ModSecurityWafRules";
    readonly OwaspTopTen2013: "OwaspTopTen2013";
    readonly HipaaCompliance: "HIPAACompliance";
    readonly Pci32: "Pci32";
    readonly KnowledgeBase: "KnowledgeBase";
    readonly ExecutiveSummary: "ExecutiveSummary";
    readonly FullScanDetail: "FullScanDetail";
    readonly OwaspTopTen2017: "OwaspTopTen2017";
    readonly CustomReport: "CustomReport";
    readonly Iso27001Compliance: "Iso27001Compliance";
    readonly F5BigIpAsmWafRules: "F5BigIpAsmWafRules";
    readonly Wasc: "WASC";
    readonly SansTop25: "SansTop25";
    readonly Asvs40: "Asvs40";
    readonly Nistsp80053: "Nistsp80053";
    readonly DisaStig: "DisaStig";
    readonly OwaspApiTop10: "OwaspApiTop10";
    readonly OwaspTopTen2021: "OwaspTopTen2021";
    readonly VulnerabilitiesPerWebsite: "VulnerabilitiesPerWebsite";
    readonly OwaspApiTopTen2023: "OwaspApiTopTen2023";
    readonly PciDss40: "PciDss40";
};
export type ScansReportTypeEnum = typeof ScansReportTypeEnum[keyof typeof ScansReportTypeEnum];
/**
 * @export
 */
export declare const ScansReportContentFormatEnum: {
    readonly Html: "Html";
    readonly Markdown: "Markdown";
};
export type ScansReportContentFormatEnum = typeof ScansReportContentFormatEnum[keyof typeof ScansReportContentFormatEnum];
/**
 * @export
 */
export declare const ScansValidateImportedLinksFileImportTypeEnum: {
    readonly None: "None";
    readonly Fiddler: "Fiddler";
    readonly Burp: "Burp";
    readonly Swagger: "Swagger";
    readonly OwaspZap: "OwaspZap";
    readonly AspNet: "AspNet";
    readonly HttpArchive: "HttpArchive";
    readonly Wadl: "Wadl";
    readonly Wsdl: "Wsdl";
    readonly Postman: "Postman";
    readonly InvictiSessionFile: "InvictiSessionFile";
    readonly CsvImporter: "CsvImporter";
    readonly Iodocs: "Iodocs";
    readonly WordPress: "WordPress";
    readonly Raml: "Raml";
    readonly GraphQl: "GraphQl";
};
export type ScansValidateImportedLinksFileImportTypeEnum = typeof ScansValidateImportedLinksFileImportTypeEnum[keyof typeof ScansValidateImportedLinksFileImportTypeEnum];
