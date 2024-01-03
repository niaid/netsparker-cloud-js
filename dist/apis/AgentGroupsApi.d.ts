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
import type { AgentGroupApiDeleteModel, AgentGroupApiNewModel, AgentGroupApiUpdateModel, AgentGroupModel, AgentGroupsListApiResult } from '../models/index';
export interface AgentGroupsApiAgentGroupsDeleteRequest {
    model: AgentGroupApiDeleteModel;
}
export interface AgentGroupsApiAgentGroupsListRequest {
    page?: number;
    pageSize?: number;
}
export interface AgentGroupsApiAgentGroupsNewRequest {
    model: AgentGroupApiNewModel;
}
export interface AgentGroupsApiAgentGroupsUpdateRequest {
    model: AgentGroupApiUpdateModel;
}
/**
 *
 */
export declare class AgentGroupsApi extends runtime.BaseAPI {
    /**
     * Deletes the agent group
     */
    agentGroupsDeleteRaw(requestParameters: AgentGroupsApiAgentGroupsDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>>;
    /**
     * Deletes the agent group
     */
    agentGroupsDelete(requestParameters: AgentGroupsApiAgentGroupsDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object>;
    /**
     * Gets the list of agent groups.
     */
    agentGroupsListRaw(requestParameters: AgentGroupsApiAgentGroupsListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<AgentGroupsListApiResult>>;
    /**
     * Gets the list of agent groups.
     */
    agentGroupsList(requestParameters?: AgentGroupsApiAgentGroupsListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<AgentGroupsListApiResult>;
    /**
     * Creates a new agent group
     */
    agentGroupsNewRaw(requestParameters: AgentGroupsApiAgentGroupsNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<AgentGroupModel>>;
    /**
     * Creates a new agent group
     */
    agentGroupsNew(requestParameters: AgentGroupsApiAgentGroupsNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<AgentGroupModel>;
    /**
     * Updates the agent group
     */
    agentGroupsUpdateRaw(requestParameters: AgentGroupsApiAgentGroupsUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<AgentGroupModel>>;
    /**
     * Updates the agent group
     */
    agentGroupsUpdate(requestParameters: AgentGroupsApiAgentGroupsUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<AgentGroupModel>;
}
