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
import type { NewTeamApiModel, TeamApiModelListApiResult, TeamApiViewModel, UpdateTeamApiModel } from '../models/index';
export interface TeamDeleteRequest {
    id: string;
}
export interface TeamGetRequest {
    id: string;
}
export interface TeamListRequest {
    page?: number;
    pageSize?: number;
}
export interface TeamNewRequest {
    model: NewTeamApiModel;
}
export interface TeamUpdateRequest {
    model: UpdateTeamApiModel;
}
/**
 *
 */
export declare class TeamApi extends runtime.BaseAPI {
    /**
     * Deletes a team
     */
    teamDeleteRaw(requestParameters: TeamDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>>;
    /**
     * Deletes a team
     */
    teamDelete(requestParameters: TeamDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string>;
    /**
     * Gets the team by the specified id.
     */
    teamGetRaw(requestParameters: TeamGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<TeamApiViewModel>>;
    /**
     * Gets the team by the specified id.
     */
    teamGet(requestParameters: TeamGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<TeamApiViewModel>;
    /**
     * Gets the list of teams.
     */
    teamListRaw(requestParameters: TeamListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<TeamApiModelListApiResult>>;
    /**
     * Gets the list of teams.
     */
    teamList(requestParameters?: TeamListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<TeamApiModelListApiResult>;
    /**
     * Creates a new team
     */
    teamNewRaw(requestParameters: TeamNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<TeamApiViewModel>>;
    /**
     * Creates a new team
     */
    teamNew(requestParameters: TeamNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<TeamApiViewModel>;
    /**
     * Updates a team
     */
    teamUpdateRaw(requestParameters: TeamUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<TeamApiViewModel>>;
    /**
     * Updates a team
     */
    teamUpdate(requestParameters: TeamUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<TeamApiViewModel>;
}
