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
import type { AgentListApiResult, AgentStatusModel, DeleteAgentModel } from '../models/index';
export interface AgentsDeleteRequest {
    model: DeleteAgentModel;
}
export interface AgentsListRequest {
    page?: number;
    pageSize?: number;
}
export interface AgentsSetStatusRequest {
    model: AgentStatusModel;
}
/**
 *
 */
export declare class AgentsApi extends runtime.BaseAPI {
    /**
     * Sets agent status as terminated.  Before deleting an agent, please make sure that you\'ve stopped the related service from the Windows Services Manager screen.  If it is running, the agent will reappear on the page despite removal.
     */
    agentsDeleteRaw(requestParameters: AgentsDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>>;
    /**
     * Sets agent status as terminated.  Before deleting an agent, please make sure that you\'ve stopped the related service from the Windows Services Manager screen.  If it is running, the agent will reappear on the page despite removal.
     */
    agentsDelete(requestParameters: AgentsDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void>;
    /**
     * Gets the list of agents.
     */
    agentsListRaw(requestParameters: AgentsListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<AgentListApiResult>>;
    /**
     * Gets the list of agents.
     */
    agentsList(requestParameters?: AgentsListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<AgentListApiResult>;
    /**
     * Sets agent status enable or disable.
     */
    agentsSetStatusRaw(requestParameters: AgentsSetStatusRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>>;
    /**
     * Sets agent status enable or disable.
     */
    agentsSetStatus(requestParameters: AgentsSetStatusRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void>;
}
