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
import type { AccountLicenseApiModel, ScanControlApiModel, UserHealthCheckApiModel } from '../models/index';
export interface AccountLicenseValidateRequest {
    username: string;
}
export interface AccountScanControl0Request {
    model: ScanControlApiModel;
}
/**
 *
 */
export declare class AccountApi extends runtime.BaseAPI {
    /**
     * Gives user\'s account license.
     */
    accountLicenseRaw(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<AccountLicenseApiModel>>;
    /**
     * Gives user\'s account license.
     */
    accountLicense(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<AccountLicenseApiModel>;
    /**
     * If user info and license validated it returns success, otherwise fails
     */
    accountLicenseValidateRaw(requestParameters: AccountLicenseValidateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>>;
    /**
     * If user info and license validated it returns success, otherwise fails
     */
    accountLicenseValidate(requestParameters: AccountLicenseValidateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void>;
    /**
     * Gets the information of callee
     */
    accountMeRaw(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<UserHealthCheckApiModel>>;
    /**
     * Gets the information of callee
     */
    accountMe(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<UserHealthCheckApiModel>;
    /**
     * Gets the scan control settings of account
     */
    accountScanControlRaw(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>>;
    /**
     * Gets the scan control settings of account
     */
    accountScanControl(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object>;
    /**
     */
    accountScanControlProgressRaw(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>>;
    /**
     */
    accountScanControlProgress(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object>;
    /**
     * Sets the scan control settings of account
     */
    accountScanControl_1Raw(requestParameters: AccountScanControl0Request, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>>;
    /**
     * Sets the scan control settings of account
     */
    accountScanControl_1(requestParameters: AccountScanControl0Request, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object>;
}
