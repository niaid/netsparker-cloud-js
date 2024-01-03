"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AccountApi = void 0;
const runtime = __importStar(require("../runtime"));
const index_1 = require("../models/index");
/**
 *
 */
class AccountApi extends runtime.BaseAPI {
    /**
     * Gives user\'s account license.
     */
    async accountLicenseRaw(initOverrides) {
        const queryParameters = {};
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/account/license`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => (0, index_1.AccountLicenseApiModelFromJSON)(jsonValue));
    }
    /**
     * Gives user\'s account license.
     */
    async accountLicense(initOverrides) {
        const response = await this.accountLicenseRaw(initOverrides);
        return await response.value();
    }
    /**
     * If user info and license validated it returns success, otherwise fails
     */
    async accountLicenseValidateRaw(requestParameters, initOverrides) {
        if (requestParameters.username === null || requestParameters.username === undefined) {
            throw new runtime.RequiredError('username', 'Required parameter requestParameters.username was null or undefined when calling accountLicenseValidate.');
        }
        const queryParameters = {};
        if (requestParameters.username !== undefined) {
            queryParameters['username'] = requestParameters.username;
        }
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/account/license-validate`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.VoidApiResponse(response);
    }
    /**
     * If user info and license validated it returns success, otherwise fails
     */
    async accountLicenseValidate(requestParameters, initOverrides) {
        await this.accountLicenseValidateRaw(requestParameters, initOverrides);
    }
    /**
     * Gets the information of callee
     */
    async accountMeRaw(initOverrides) {
        const queryParameters = {};
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/account/me`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => (0, index_1.UserHealthCheckApiModelFromJSON)(jsonValue));
    }
    /**
     * Gets the information of callee
     */
    async accountMe(initOverrides) {
        const response = await this.accountMeRaw(initOverrides);
        return await response.value();
    }
    /**
     * Gets the scan control settings of account
     */
    async accountScanControlRaw(initOverrides) {
        const queryParameters = {};
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/account/scan-control`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response);
    }
    /**
     * Gets the scan control settings of account
     */
    async accountScanControl(initOverrides) {
        const response = await this.accountScanControlRaw(initOverrides);
        return await response.value();
    }
    /**
     */
    async accountScanControlProgressRaw(initOverrides) {
        const queryParameters = {};
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/account/scan-control-progress`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response);
    }
    /**
     */
    async accountScanControlProgress(initOverrides) {
        const response = await this.accountScanControlProgressRaw(initOverrides);
        return await response.value();
    }
    /**
     * Sets the scan control settings of account
     */
    async accountScanControl_1Raw(requestParameters, initOverrides) {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model', 'Required parameter requestParameters.model was null or undefined when calling accountScanControl_1.');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/account/scan-control`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: (0, index_1.ScanControlApiModelToJSON)(requestParameters.model),
        }, initOverrides);
        return new runtime.JSONApiResponse(response);
    }
    /**
     * Sets the scan control settings of account
     */
    async accountScanControl_1(requestParameters, initOverrides) {
        const response = await this.accountScanControl_1Raw(requestParameters, initOverrides);
        return await response.value();
    }
}
exports.AccountApi = AccountApi;
//# sourceMappingURL=AccountApi.js.map