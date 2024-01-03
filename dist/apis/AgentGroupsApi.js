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
import * as runtime from '../runtime';
import { AgentGroupApiDeleteModelToJSON, AgentGroupApiNewModelToJSON, AgentGroupApiUpdateModelToJSON, AgentGroupModelFromJSON, AgentGroupsListApiResultFromJSON, } from '../models/index';
/**
 *
 */
export class AgentGroupsApi extends runtime.BaseAPI {
    /**
     * Deletes the agent group
     */
    async agentGroupsDeleteRaw(requestParameters, initOverrides) {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model', 'Required parameter requestParameters.model was null or undefined when calling agentGroupsDelete.');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/agentgroups/delete`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: AgentGroupApiDeleteModelToJSON(requestParameters.model),
        }, initOverrides);
        return new runtime.JSONApiResponse(response);
    }
    /**
     * Deletes the agent group
     */
    async agentGroupsDelete(requestParameters, initOverrides) {
        const response = await this.agentGroupsDeleteRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Gets the list of agent groups.
     */
    async agentGroupsListRaw(requestParameters, initOverrides) {
        const queryParameters = {};
        if (requestParameters.page !== undefined) {
            queryParameters['page'] = requestParameters.page;
        }
        if (requestParameters.pageSize !== undefined) {
            queryParameters['pageSize'] = requestParameters.pageSize;
        }
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/agentgroups/list`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => AgentGroupsListApiResultFromJSON(jsonValue));
    }
    /**
     * Gets the list of agent groups.
     */
    async agentGroupsList(requestParameters = {}, initOverrides) {
        const response = await this.agentGroupsListRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Creates a new agent group
     */
    async agentGroupsNewRaw(requestParameters, initOverrides) {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model', 'Required parameter requestParameters.model was null or undefined when calling agentGroupsNew.');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/agentgroups/new`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: AgentGroupApiNewModelToJSON(requestParameters.model),
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => AgentGroupModelFromJSON(jsonValue));
    }
    /**
     * Creates a new agent group
     */
    async agentGroupsNew(requestParameters, initOverrides) {
        const response = await this.agentGroupsNewRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Updates the agent group
     */
    async agentGroupsUpdateRaw(requestParameters, initOverrides) {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model', 'Required parameter requestParameters.model was null or undefined when calling agentGroupsUpdate.');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/agentgroups/update`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: AgentGroupApiUpdateModelToJSON(requestParameters.model),
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => AgentGroupModelFromJSON(jsonValue));
    }
    /**
     * Updates the agent group
     */
    async agentGroupsUpdate(requestParameters, initOverrides) {
        const response = await this.agentGroupsUpdateRaw(requestParameters, initOverrides);
        return await response.value();
    }
}
//# sourceMappingURL=AgentGroupsApi.js.map