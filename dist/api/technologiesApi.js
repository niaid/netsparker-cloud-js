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
exports.TechnologiesApi = exports.TechnologiesApiApiKeys = void 0;
const request_1 = __importDefault(require("request"));
const models_1 = require("../model/models");
const apis_1 = require("./apis");
let defaultBasePath = 'https://www.netsparkercloud.com';
// ===============================================
// This file is autogenerated - Please do not edit
// ===============================================
var TechnologiesApiApiKeys;
(function (TechnologiesApiApiKeys) {
})(TechnologiesApiApiKeys = exports.TechnologiesApiApiKeys || (exports.TechnologiesApiApiKeys = {}));
class TechnologiesApi {
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
        this.authentications[TechnologiesApiApiKeys[key]].apiKey = value;
    }
    addInterceptor(interceptor) {
        this.interceptors.push(interceptor);
    }
    /**
     *
     * @summary Gets the list of technologies that currently in use.
     * @param webSiteName The website\&#39;s name.
     * @param technologyName The technology\&#39;s display name.
     * @param page The page size.
     * @param pageSize The page size. Page size can be any value between 1 and 200.
     */
    async technologiesList(webSiteName, technologyName, page, pageSize, options = { headers: {} }) {
        const localVarPath = this.basePath + '/api/1.0/technologies/list';
        let localVarQueryParameters = {};
        let localVarHeaderParams = Object.assign({}, this._defaultHeaders);
        const produces = ['application/json', 'text/json', 'application/scim+json', 'application/xml', 'text/xml', 'multipart/form-data'];
        // give precedence to 'application/json'
        if (produces.indexOf('application/json') >= 0) {
            localVarHeaderParams.Accept = 'application/json';
        }
        else {
            localVarHeaderParams.Accept = produces.join(',');
        }
        let localVarFormParams = {};
        if (webSiteName !== undefined) {
            localVarQueryParameters['webSiteName'] = models_1.ObjectSerializer.serialize(webSiteName, "string");
        }
        if (technologyName !== undefined) {
            localVarQueryParameters['technologyName'] = models_1.ObjectSerializer.serialize(technologyName, "string");
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
                        body = models_1.ObjectSerializer.deserialize(body, "TechnologyListApiResult");
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
     * @summary Gets the list of out-of-date technologies that currently in use.
     * @param webSiteName The website\&#39;s name.
     * @param technologyName The technology\&#39;s display name.
     * @param page The page size.
     * @param pageSize The page size. Page size can be any value between 1 and 200.
     */
    async technologiesOutofdateTechnologies(webSiteName, technologyName, page, pageSize, options = { headers: {} }) {
        const localVarPath = this.basePath + '/api/1.0/technologies/outofdatetechnologies';
        let localVarQueryParameters = {};
        let localVarHeaderParams = Object.assign({}, this._defaultHeaders);
        const produces = ['application/json', 'text/json', 'application/scim+json', 'application/xml', 'text/xml', 'multipart/form-data'];
        // give precedence to 'application/json'
        if (produces.indexOf('application/json') >= 0) {
            localVarHeaderParams.Accept = 'application/json';
        }
        else {
            localVarHeaderParams.Accept = produces.join(',');
        }
        let localVarFormParams = {};
        if (webSiteName !== undefined) {
            localVarQueryParameters['webSiteName'] = models_1.ObjectSerializer.serialize(webSiteName, "string");
        }
        if (technologyName !== undefined) {
            localVarQueryParameters['technologyName'] = models_1.ObjectSerializer.serialize(technologyName, "string");
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
                        body = models_1.ObjectSerializer.deserialize(body, "TechnologyListApiResult");
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
exports.TechnologiesApi = TechnologiesApi;
//# sourceMappingURL=technologiesApi.js.map