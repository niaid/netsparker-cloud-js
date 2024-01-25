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
exports.AgentsApi = void 0;
const runtime = __importStar(require("../runtime"));
const index_1 = require("../models/index");
/**
 *
 */
class AgentsApi extends runtime.BaseAPI {
    /**
     * Sets agent status as terminated.  Before deleting an agent, please make sure that you\'ve stopped the related service from the Windows Services Manager screen.  If it is running, the agent will reappear on the page despite removal.
     */
    async agentsDeleteRaw(requestParameters, initOverrides) {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model', 'Required parameter requestParameters.model was null or undefined when calling agentsDelete.');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/agents/delete`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: (0, index_1.DeleteAgentModelToJSON)(requestParameters.model),
        }, initOverrides);
        return new runtime.VoidApiResponse(response);
    }
    /**
     * Sets agent status as terminated.  Before deleting an agent, please make sure that you\'ve stopped the related service from the Windows Services Manager screen.  If it is running, the agent will reappear on the page despite removal.
     */
    async agentsDelete(requestParameters, initOverrides) {
        await this.agentsDeleteRaw(requestParameters, initOverrides);
    }
    /**
     * Gets the list of agents.
     */
    async agentsListRaw(requestParameters, initOverrides) {
        const queryParameters = {};
        if (requestParameters.page !== undefined) {
            queryParameters['page'] = requestParameters.page;
        }
        if (requestParameters.pageSize !== undefined) {
            queryParameters['pageSize'] = requestParameters.pageSize;
        }
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/agents/list`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => (0, index_1.AgentListApiResultFromJSON)(jsonValue));
    }
    /**
     * Gets the list of agents.
     */
    async agentsList(requestParameters = {}, initOverrides) {
        const response = await this.agentsListRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Sets agent status enable or disable.
     */
    async agentsSetStatusRaw(requestParameters, initOverrides) {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model', 'Required parameter requestParameters.model was null or undefined when calling agentsSetStatus.');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/agents/setstatus`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: (0, index_1.AgentStatusModelToJSON)(requestParameters.model),
        }, initOverrides);
        return new runtime.VoidApiResponse(response);
    }
    /**
     * Sets agent status enable or disable.
     */
    async agentsSetStatus(requestParameters, initOverrides) {
        await this.agentsSetStatusRaw(requestParameters, initOverrides);
    }
}
exports.AgentsApi = AgentsApi;
//# sourceMappingURL=AgentsApi.js.map