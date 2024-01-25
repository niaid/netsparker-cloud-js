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
exports.CustomScriptApi = void 0;
const runtime = __importStar(require("../runtime"));
const index_1 = require("../models/index");
/**
 *
 */
class CustomScriptApi extends runtime.BaseAPI {
    /**
     * Deletes Custom Scripts
     */
    async customScriptDeleteRaw(requestParameters, initOverrides) {
        if (requestParameters.ids === null || requestParameters.ids === undefined) {
            throw new runtime.RequiredError('ids', 'Required parameter requestParameters.ids was null or undefined when calling customScriptDelete.');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/customscript/delete`,
            method: 'DELETE',
            headers: headerParameters,
            query: queryParameters,
            body: requestParameters.ids,
        }, initOverrides);
        return new runtime.JSONApiResponse(response);
    }
    /**
     * Deletes Custom Scripts
     */
    async customScriptDelete(requestParameters, initOverrides) {
        const response = await this.customScriptDeleteRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Lists Custom Scripts
     */
    async customScriptListRaw(initOverrides) {
        const queryParameters = {};
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/customscript/list`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response);
    }
    /**
     * Lists Custom Scripts
     */
    async customScriptList(initOverrides) {
        const response = await this.customScriptListRaw(initOverrides);
        return await response.value();
    }
    /**
     * Creates Custom Scripts
     */
    async customScriptNewRaw(requestParameters, initOverrides) {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model', 'Required parameter requestParameters.model was null or undefined when calling customScriptNew.');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/customscript/new`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: requestParameters.model.map(index_1.CustomScriptRequestApiModelToJSON),
        }, initOverrides);
        return new runtime.JSONApiResponse(response);
    }
    /**
     * Creates Custom Scripts
     */
    async customScriptNew(requestParameters, initOverrides) {
        const response = await this.customScriptNewRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Updates Custom Scripts
     */
    async customScriptUpdateRaw(requestParameters, initOverrides) {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model', 'Required parameter requestParameters.model was null or undefined when calling customScriptUpdate.');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/customscript/update`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: requestParameters.model.map(index_1.CustomScriptUpdateRequestApiModelToJSON),
        }, initOverrides);
        return new runtime.JSONApiResponse(response);
    }
    /**
     * Updates Custom Scripts
     */
    async customScriptUpdate(requestParameters, initOverrides) {
        const response = await this.customScriptUpdateRaw(requestParameters, initOverrides);
        return await response.value();
    }
}
exports.CustomScriptApi = CustomScriptApi;
//# sourceMappingURL=CustomScriptApi.js.map