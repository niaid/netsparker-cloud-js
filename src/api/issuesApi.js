"use strict";
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.IssuesApi = exports.IssuesApiApiKeys = void 0;
const request_1 = __importDefault(require("request"));
const models_1 = require("../model/models");
const apis_1 = require("./apis");
let defaultBasePath = 'https://www.netsparkercloud.com';
// ===============================================
// This file is autogenerated - Please do not edit
// ===============================================
var IssuesApiApiKeys;
(function (IssuesApiApiKeys) {
})(IssuesApiApiKeys = exports.IssuesApiApiKeys || (exports.IssuesApiApiKeys = {}));
class IssuesApi {
    constructor(basePathOrUsername, password, basePath) {
        this._basePath = defaultBasePath;
        this._defaultHeaders = {};
        this._useQuerystring = false;
        this.authentications = {
            'default': new models_1.VoidAuth(),
        };
        this.interceptors = [];
        if (password) {
            if (basePath) {
                this.basePath = basePath;
            }
        }
        else {
            if (basePathOrUsername) {
                this.basePath = basePathOrUsername;
            }
        }
    }
    set useQuerystring(value) {
        this._useQuerystring = value;
    }
    set basePath(basePath) {
        this._basePath = basePath;
    }
    set defaultHeaders(defaultHeaders) {
        this._defaultHeaders = defaultHeaders;
    }
    get defaultHeaders() {
        return this._defaultHeaders;
    }
    get basePath() {
        return this._basePath;
    }
    setDefaultAuthentication(auth) {
        this.authentications.default = auth;
    }
    setApiKey(key, value) {
        this.authentications[IssuesApiApiKeys[key]].apiKey = value;
    }
    addInterceptor(interceptor) {
        this.interceptors.push(interceptor);
    }
    /**
     *
     * @summary Gets the list of addressed issues.
     * @param severity The vulnerability severity
     * @param webSiteName The website\&#39;s name.
     * @param websiteGroupName The website group\&#39;s name.
     * @param page The page size.
     * @param pageSize The page size. Page size can be any value between 1 and 200.
     */
    async issuesAddressedIssues(severity, webSiteName, websiteGroupName, page, pageSize, options = { headers: {} }) {
        const localVarPath = this.basePath + '/api/1.0/issues/addressedissues';
        let localVarQueryParameters = {};
        let localVarHeaderParams = Object.assign({}, this._defaultHeaders);
        const produces = ['application/json', 'text/json', 'application/xml', 'text/xml', 'multipart/form-data'];
        // give precedence to 'application/json'
        if (produces.indexOf('application/json') >= 0) {
            localVarHeaderParams.Accept = 'application/json';
        }
        else {
            localVarHeaderParams.Accept = produces.join(',');
        }
        let localVarFormParams = {};
        if (severity !== undefined) {
            localVarQueryParameters['severity'] = models_1.ObjectSerializer.serialize(severity, "'BestPractice' | 'Information' | 'Low' | 'Medium' | 'High' | 'Critical'");
        }
        if (webSiteName !== undefined) {
            localVarQueryParameters['webSiteName'] = models_1.ObjectSerializer.serialize(webSiteName, "string");
        }
        if (websiteGroupName !== undefined) {
            localVarQueryParameters['websiteGroupName'] = models_1.ObjectSerializer.serialize(websiteGroupName, "string");
        }
        if (page !== undefined) {
            localVarQueryParameters['page'] = models_1.ObjectSerializer.serialize(page, "number");
        }
        if (pageSize !== undefined) {
            localVarQueryParameters['pageSize'] = models_1.ObjectSerializer.serialize(pageSize, "number");
        }
        Object.assign(localVarHeaderParams, options.headers);
        let localVarUseFormData = false;
        let localVarRequestOptions = {
            method: 'GET',
            qs: localVarQueryParameters,
            headers: localVarHeaderParams,
            uri: localVarPath,
            useQuerystring: this._useQuerystring,
            json: true,
        };
        let authenticationPromise = Promise.resolve();
        authenticationPromise = authenticationPromise.then(() => this.authentications.default.applyToRequest(localVarRequestOptions));
        let interceptorPromise = authenticationPromise;
        for (const interceptor of this.interceptors) {
            interceptorPromise = interceptorPromise.then(() => interceptor(localVarRequestOptions));
        }
        return interceptorPromise.then(() => {
            if (Object.keys(localVarFormParams).length) {
                if (localVarUseFormData) {
                    localVarRequestOptions.formData = localVarFormParams;
                }
                else {
                    localVarRequestOptions.form = localVarFormParams;
                }
            }
            return new Promise((resolve, reject) => {
                request_1.default(localVarRequestOptions, (error, response, body) => {
                    if (error) {
                        reject(error);
                    }
                    else {
                        body = models_1.ObjectSerializer.deserialize(body, "IssueApiResult");
                        if (response.statusCode && response.statusCode >= 200 && response.statusCode <= 299) {
                            resolve({ response: response, body: body });
                        }
                        else {
                            reject(new apis_1.HttpError(response, body, response.statusCode));
                        }
                    }
                });
            });
        });
    }
    /**
     *
     * @summary Gets the list of all issues.
     * @param severity The vulnerability severity
     * @param webSiteName The website\&#39;s name.
     * @param websiteGroupName The website group\&#39;s name.
     * @param page The page size.
     * @param pageSize The page size. Page size can be any value between 1 and 200.
     * @param sortType Sort by ascending and descending according to LastSeenDate. Default parameter ascending.
     * @param lastSeenDate You can use the date format defined in your account. You can visit /account/changesettings to view the current format.
     * @param rawDetails If you want the vulnerability data response(Remedy, Description etc.) to return without raw html, this field must be set false.
     */
    async issuesAllIssues(severity, webSiteName, websiteGroupName, page, pageSize, sortType, lastSeenDate, rawDetails, options = { headers: {} }) {
        const localVarPath = this.basePath + '/api/1.0/issues/allissues';
        let localVarQueryParameters = {};
        let localVarHeaderParams = Object.assign({}, this._defaultHeaders);
        const produces = ['application/json', 'text/json', 'application/xml', 'text/xml', 'multipart/form-data'];
        // give precedence to 'application/json'
        if (produces.indexOf('application/json') >= 0) {
            localVarHeaderParams.Accept = 'application/json';
        }
        else {
            localVarHeaderParams.Accept = produces.join(',');
        }
        let localVarFormParams = {};
        if (severity !== undefined) {
            localVarQueryParameters['severity'] = models_1.ObjectSerializer.serialize(severity, "'BestPractice' | 'Information' | 'Low' | 'Medium' | 'High' | 'Critical'");
        }
        if (webSiteName !== undefined) {
            localVarQueryParameters['webSiteName'] = models_1.ObjectSerializer.serialize(webSiteName, "string");
        }
        if (websiteGroupName !== undefined) {
            localVarQueryParameters['websiteGroupName'] = models_1.ObjectSerializer.serialize(websiteGroupName, "string");
        }
        if (page !== undefined) {
            localVarQueryParameters['page'] = models_1.ObjectSerializer.serialize(page, "number");
        }
        if (pageSize !== undefined) {
            localVarQueryParameters['pageSize'] = models_1.ObjectSerializer.serialize(pageSize, "number");
        }
        if (sortType !== undefined) {
            localVarQueryParameters['sortType'] = models_1.ObjectSerializer.serialize(sortType, "'Ascending' | 'Descending'");
        }
        if (lastSeenDate !== undefined) {
            localVarQueryParameters['lastSeenDate'] = models_1.ObjectSerializer.serialize(lastSeenDate, "string");
        }
        if (rawDetails !== undefined) {
            localVarQueryParameters['rawDetails'] = models_1.ObjectSerializer.serialize(rawDetails, "boolean");
        }
        Object.assign(localVarHeaderParams, options.headers);
        let localVarUseFormData = false;
        let localVarRequestOptions = {
            method: 'GET',
            qs: localVarQueryParameters,
            headers: localVarHeaderParams,
            uri: localVarPath,
            useQuerystring: this._useQuerystring,
            json: true,
        };
        let authenticationPromise = Promise.resolve();
        authenticationPromise = authenticationPromise.then(() => this.authentications.default.applyToRequest(localVarRequestOptions));
        let interceptorPromise = authenticationPromise;
        for (const interceptor of this.interceptors) {
            interceptorPromise = interceptorPromise.then(() => interceptor(localVarRequestOptions));
        }
        return interceptorPromise.then(() => {
            if (Object.keys(localVarFormParams).length) {
                if (localVarUseFormData) {
                    localVarRequestOptions.formData = localVarFormParams;
                }
                else {
                    localVarRequestOptions.form = localVarFormParams;
                }
            }
            return new Promise((resolve, reject) => {
                request_1.default(localVarRequestOptions, (error, response, body) => {
                    if (error) {
                        reject(error);
                    }
                    else {
                        body = models_1.ObjectSerializer.deserialize(body, "IssueApiResult");
                        if (response.statusCode && response.statusCode >= 200 && response.statusCode <= 299) {
                            resolve({ response: response, body: body });
                        }
                        else {
                            reject(new apis_1.HttpError(response, body, response.statusCode));
                        }
                    }
                });
            });
        });
    }
    /**
     *
     * @summary Gets issues by id. Returns with encoded(raw html) vulnerability template data by default.
     * @param id id.
     */
    async issuesGet(id, options = { headers: {} }) {
        const localVarPath = this.basePath + '/api/1.0/issues/get/{id}'
            .replace('{' + 'id' + '}', encodeURIComponent(String(id)));
        let localVarQueryParameters = {};
        let localVarHeaderParams = Object.assign({}, this._defaultHeaders);
        const produces = ['application/json', 'text/json', 'application/xml', 'text/xml', 'multipart/form-data'];
        // give precedence to 'application/json'
        if (produces.indexOf('application/json') >= 0) {
            localVarHeaderParams.Accept = 'application/json';
        }
        else {
            localVarHeaderParams.Accept = produces.join(',');
        }
        let localVarFormParams = {};
        // verify required parameter 'id' is not null or undefined
        if (id === null || id === undefined) {
            throw new Error('Required parameter id was null or undefined when calling issuesGet.');
        }
        Object.assign(localVarHeaderParams, options.headers);
        let localVarUseFormData = false;
        let localVarRequestOptions = {
            method: 'GET',
            qs: localVarQueryParameters,
            headers: localVarHeaderParams,
            uri: localVarPath,
            useQuerystring: this._useQuerystring,
            json: true,
        };
        let authenticationPromise = Promise.resolve();
        authenticationPromise = authenticationPromise.then(() => this.authentications.default.applyToRequest(localVarRequestOptions));
        let interceptorPromise = authenticationPromise;
        for (const interceptor of this.interceptors) {
            interceptorPromise = interceptorPromise.then(() => interceptor(localVarRequestOptions));
        }
        return interceptorPromise.then(() => {
            if (Object.keys(localVarFormParams).length) {
                if (localVarUseFormData) {
                    localVarRequestOptions.formData = localVarFormParams;
                }
                else {
                    localVarRequestOptions.form = localVarFormParams;
                }
            }
            return new Promise((resolve, reject) => {
                request_1.default(localVarRequestOptions, (error, response, body) => {
                    if (error) {
                        reject(error);
                    }
                    else {
                        body = models_1.ObjectSerializer.deserialize(body, "IssueApiModel");
                        if (response.statusCode && response.statusCode >= 200 && response.statusCode <= 299) {
                            resolve({ response: response, body: body });
                        }
                        else {
                            reject(new apis_1.HttpError(response, body, response.statusCode));
                        }
                    }
                });
            });
        });
    }
    /**
     *
     * @summary Gets vulnerability request/response content by id.
     * @param id id.
     */
    async issuesGetVulnerabilityContent(id, options = { headers: {} }) {
        const localVarPath = this.basePath + '/api/1.0/issues/getvulnerabilitycontent/{id}'
            .replace('{' + 'id' + '}', encodeURIComponent(String(id)));
        let localVarQueryParameters = {};
        let localVarHeaderParams = Object.assign({}, this._defaultHeaders);
        const produces = ['application/json', 'text/json', 'application/xml', 'text/xml', 'multipart/form-data'];
        // give precedence to 'application/json'
        if (produces.indexOf('application/json') >= 0) {
            localVarHeaderParams.Accept = 'application/json';
        }
        else {
            localVarHeaderParams.Accept = produces.join(',');
        }
        let localVarFormParams = {};
        // verify required parameter 'id' is not null or undefined
        if (id === null || id === undefined) {
            throw new Error('Required parameter id was null or undefined when calling issuesGetVulnerabilityContent.');
        }
        Object.assign(localVarHeaderParams, options.headers);
        let localVarUseFormData = false;
        let localVarRequestOptions = {
            method: 'GET',
            qs: localVarQueryParameters,
            headers: localVarHeaderParams,
            uri: localVarPath,
            useQuerystring: this._useQuerystring,
            json: true,
        };
        let authenticationPromise = Promise.resolve();
        authenticationPromise = authenticationPromise.then(() => this.authentications.default.applyToRequest(localVarRequestOptions));
        let interceptorPromise = authenticationPromise;
        for (const interceptor of this.interceptors) {
            interceptorPromise = interceptorPromise.then(() => interceptor(localVarRequestOptions));
        }
        return interceptorPromise.then(() => {
            if (Object.keys(localVarFormParams).length) {
                if (localVarUseFormData) {
                    localVarRequestOptions.formData = localVarFormParams;
                }
                else {
                    localVarRequestOptions.form = localVarFormParams;
                }
            }
            return new Promise((resolve, reject) => {
                request_1.default(localVarRequestOptions, (error, response, body) => {
                    if (error) {
                        reject(error);
                    }
                    else {
                        body = models_1.ObjectSerializer.deserialize(body, "VulnerabilityContentApiModel");
                        if (response.statusCode && response.statusCode >= 200 && response.statusCode <= 299) {
                            resolve({ response: response, body: body });
                        }
                        else {
                            reject(new apis_1.HttpError(response, body, response.statusCode));
                        }
                    }
                });
            });
        });
    }
    /**
     *
     * @summary Returns the report of issues in the csv format.
     * @param csvSeparator Gets or sets the csv separator.
     * @param severity Gets or sets the vulnerability\&#39;s severity.
     * @param websiteGroupName Gets or sets the website group\&#39;s name.
     * @param webSiteName Gets or sets the website\&#39;s name.
     */
    async issuesReport(csvSeparator, severity, websiteGroupName, webSiteName, options = { headers: {} }) {
        const localVarPath = this.basePath + '/api/1.0/issues/report';
        let localVarQueryParameters = {};
        let localVarHeaderParams = Object.assign({}, this._defaultHeaders);
        let localVarFormParams = {};
        if (csvSeparator !== undefined) {
            localVarQueryParameters['csvSeparator'] = models_1.ObjectSerializer.serialize(csvSeparator, "'Comma' | 'Semicolon' | 'Pipe' | 'Tab'");
        }
        if (severity !== undefined) {
            localVarQueryParameters['severity'] = models_1.ObjectSerializer.serialize(severity, "'BestPractice' | 'Information' | 'Low' | 'Medium' | 'High' | 'Critical'");
        }
        if (websiteGroupName !== undefined) {
            localVarQueryParameters['websiteGroupName'] = models_1.ObjectSerializer.serialize(websiteGroupName, "string");
        }
        if (webSiteName !== undefined) {
            localVarQueryParameters['webSiteName'] = models_1.ObjectSerializer.serialize(webSiteName, "string");
        }
        Object.assign(localVarHeaderParams, options.headers);
        let localVarUseFormData = false;
        let localVarRequestOptions = {
            method: 'GET',
            qs: localVarQueryParameters,
            headers: localVarHeaderParams,
            uri: localVarPath,
            useQuerystring: this._useQuerystring,
            json: true,
        };
        let authenticationPromise = Promise.resolve();
        authenticationPromise = authenticationPromise.then(() => this.authentications.default.applyToRequest(localVarRequestOptions));
        let interceptorPromise = authenticationPromise;
        for (const interceptor of this.interceptors) {
            interceptorPromise = interceptorPromise.then(() => interceptor(localVarRequestOptions));
        }
        return interceptorPromise.then(() => {
            if (Object.keys(localVarFormParams).length) {
                if (localVarUseFormData) {
                    localVarRequestOptions.formData = localVarFormParams;
                }
                else {
                    localVarRequestOptions.form = localVarFormParams;
                }
            }
            return new Promise((resolve, reject) => {
                request_1.default(localVarRequestOptions, (error, response, body) => {
                    if (error) {
                        reject(error);
                    }
                    else {
                        if (response.statusCode && response.statusCode >= 200 && response.statusCode <= 299) {
                            resolve({ response: response, body: body });
                        }
                        else {
                            reject(new apis_1.HttpError(response, body, response.statusCode));
                        }
                    }
                });
            });
        });
    }
    /**
     *
     * @summary Gets the list of to-do issues.
     * @param severity The vulnerability severity
     * @param webSiteName The website\&#39;s name.
     * @param websiteGroupName The website group\&#39;s name.
     * @param page The page size.
     * @param pageSize The page size. Page size can be any value between 1 and 200.
     */
    async issuesTodo(severity, webSiteName, websiteGroupName, page, pageSize, options = { headers: {} }) {
        const localVarPath = this.basePath + '/api/1.0/issues/todo';
        let localVarQueryParameters = {};
        let localVarHeaderParams = Object.assign({}, this._defaultHeaders);
        const produces = ['application/json', 'text/json', 'application/xml', 'text/xml', 'multipart/form-data'];
        // give precedence to 'application/json'
        if (produces.indexOf('application/json') >= 0) {
            localVarHeaderParams.Accept = 'application/json';
        }
        else {
            localVarHeaderParams.Accept = produces.join(',');
        }
        let localVarFormParams = {};
        if (severity !== undefined) {
            localVarQueryParameters['severity'] = models_1.ObjectSerializer.serialize(severity, "'BestPractice' | 'Information' | 'Low' | 'Medium' | 'High' | 'Critical'");
        }
        if (webSiteName !== undefined) {
            localVarQueryParameters['webSiteName'] = models_1.ObjectSerializer.serialize(webSiteName, "string");
        }
        if (websiteGroupName !== undefined) {
            localVarQueryParameters['websiteGroupName'] = models_1.ObjectSerializer.serialize(websiteGroupName, "string");
        }
        if (page !== undefined) {
            localVarQueryParameters['page'] = models_1.ObjectSerializer.serialize(page, "number");
        }
        if (pageSize !== undefined) {
            localVarQueryParameters['pageSize'] = models_1.ObjectSerializer.serialize(pageSize, "number");
        }
        Object.assign(localVarHeaderParams, options.headers);
        let localVarUseFormData = false;
        let localVarRequestOptions = {
            method: 'GET',
            qs: localVarQueryParameters,
            headers: localVarHeaderParams,
            uri: localVarPath,
            useQuerystring: this._useQuerystring,
            json: true,
        };
        let authenticationPromise = Promise.resolve();
        authenticationPromise = authenticationPromise.then(() => this.authentications.default.applyToRequest(localVarRequestOptions));
        let interceptorPromise = authenticationPromise;
        for (const interceptor of this.interceptors) {
            interceptorPromise = interceptorPromise.then(() => interceptor(localVarRequestOptions));
        }
        return interceptorPromise.then(() => {
            if (Object.keys(localVarFormParams).length) {
                if (localVarUseFormData) {
                    localVarRequestOptions.formData = localVarFormParams;
                }
                else {
                    localVarRequestOptions.form = localVarFormParams;
                }
            }
            return new Promise((resolve, reject) => {
                request_1.default(localVarRequestOptions, (error, response, body) => {
                    if (error) {
                        reject(error);
                    }
                    else {
                        body = models_1.ObjectSerializer.deserialize(body, "IssueApiResult");
                        if (response.statusCode && response.statusCode >= 200 && response.statusCode <= 299) {
                            resolve({ response: response, body: body });
                        }
                        else {
                            reject(new apis_1.HttpError(response, body, response.statusCode));
                        }
                    }
                });
            });
        });
    }
    /**
     *
     * @summary Updates an existing issue.
     * @param model Issue model to update. Except IssueId, all parameters are optional but at least 1 parameter is required.              To reset status send \&quot;State\&quot;: \&quot;Default\&quot;
     */
    async issuesUpdate(model, options = { headers: {} }) {
        const localVarPath = this.basePath + '/api/1.0/issues/update';
        let localVarQueryParameters = {};
        let localVarHeaderParams = Object.assign({}, this._defaultHeaders);
        let localVarFormParams = {};
        // verify required parameter 'model' is not null or undefined
        if (model === null || model === undefined) {
            throw new Error('Required parameter model was null or undefined when calling issuesUpdate.');
        }
        Object.assign(localVarHeaderParams, options.headers);
        let localVarUseFormData = false;
        let localVarRequestOptions = {
            method: 'POST',
            qs: localVarQueryParameters,
            headers: localVarHeaderParams,
            uri: localVarPath,
            useQuerystring: this._useQuerystring,
            json: true,
            body: models_1.ObjectSerializer.serialize(model, "IssueApiUpdateModel")
        };
        let authenticationPromise = Promise.resolve();
        authenticationPromise = authenticationPromise.then(() => this.authentications.default.applyToRequest(localVarRequestOptions));
        let interceptorPromise = authenticationPromise;
        for (const interceptor of this.interceptors) {
            interceptorPromise = interceptorPromise.then(() => interceptor(localVarRequestOptions));
        }
        return interceptorPromise.then(() => {
            if (Object.keys(localVarFormParams).length) {
                if (localVarUseFormData) {
                    localVarRequestOptions.formData = localVarFormParams;
                }
                else {
                    localVarRequestOptions.form = localVarFormParams;
                }
            }
            return new Promise((resolve, reject) => {
                request_1.default(localVarRequestOptions, (error, response, body) => {
                    if (error) {
                        reject(error);
                    }
                    else {
                        if (response.statusCode && response.statusCode >= 200 && response.statusCode <= 299) {
                            resolve({ response: response, body: body });
                        }
                        else {
                            reject(new apis_1.HttpError(response, body, response.statusCode));
                        }
                    }
                });
            });
        });
    }
    /**
     *
     * @summary Gets the list of retest issues.
     * @param severity The vulnerability severity
     * @param webSiteName The website\&#39;s name.
     * @param websiteGroupName The website group\&#39;s name.
     * @param page The page size.
     * @param pageSize The page size. Page size can be any value between 1 and 200.
     */
    async issuesWaitingForRetest(severity, webSiteName, websiteGroupName, page, pageSize, options = { headers: {} }) {
        const localVarPath = this.basePath + '/api/1.0/issues/waitingforretest';
        let localVarQueryParameters = {};
        let localVarHeaderParams = Object.assign({}, this._defaultHeaders);
        const produces = ['application/json', 'text/json', 'application/xml', 'text/xml', 'multipart/form-data'];
        // give precedence to 'application/json'
        if (produces.indexOf('application/json') >= 0) {
            localVarHeaderParams.Accept = 'application/json';
        }
        else {
            localVarHeaderParams.Accept = produces.join(',');
        }
        let localVarFormParams = {};
        if (severity !== undefined) {
            localVarQueryParameters['severity'] = models_1.ObjectSerializer.serialize(severity, "'BestPractice' | 'Information' | 'Low' | 'Medium' | 'High' | 'Critical'");
        }
        if (webSiteName !== undefined) {
            localVarQueryParameters['webSiteName'] = models_1.ObjectSerializer.serialize(webSiteName, "string");
        }
        if (websiteGroupName !== undefined) {
            localVarQueryParameters['websiteGroupName'] = models_1.ObjectSerializer.serialize(websiteGroupName, "string");
        }
        if (page !== undefined) {
            localVarQueryParameters['page'] = models_1.ObjectSerializer.serialize(page, "number");
        }
        if (pageSize !== undefined) {
            localVarQueryParameters['pageSize'] = models_1.ObjectSerializer.serialize(pageSize, "number");
        }
        Object.assign(localVarHeaderParams, options.headers);
        let localVarUseFormData = false;
        let localVarRequestOptions = {
            method: 'GET',
            qs: localVarQueryParameters,
            headers: localVarHeaderParams,
            uri: localVarPath,
            useQuerystring: this._useQuerystring,
            json: true,
        };
        let authenticationPromise = Promise.resolve();
        authenticationPromise = authenticationPromise.then(() => this.authentications.default.applyToRequest(localVarRequestOptions));
        let interceptorPromise = authenticationPromise;
        for (const interceptor of this.interceptors) {
            interceptorPromise = interceptorPromise.then(() => interceptor(localVarRequestOptions));
        }
        return interceptorPromise.then(() => {
            if (Object.keys(localVarFormParams).length) {
                if (localVarUseFormData) {
                    localVarRequestOptions.formData = localVarFormParams;
                }
                else {
                    localVarRequestOptions.form = localVarFormParams;
                }
            }
            return new Promise((resolve, reject) => {
                request_1.default(localVarRequestOptions, (error, response, body) => {
                    if (error) {
                        reject(error);
                    }
                    else {
                        body = models_1.ObjectSerializer.deserialize(body, "IssueApiResult");
                        if (response.statusCode && response.statusCode >= 200 && response.statusCode <= 299) {
                            resolve({ response: response, body: body });
                        }
                        else {
                            reject(new apis_1.HttpError(response, body, response.statusCode));
                        }
                    }
                });
            });
        });
    }
}
exports.IssuesApi = IssuesApi;
//# sourceMappingURL=issuesApi.js.map