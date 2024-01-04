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
exports.DiscoveryListByFilterStatusEnum = exports.DiscoveryExportCsvSeparatorEnum = exports.DiscoveryConnectionsTypeEnum = exports.DiscoveryConnectionByIdTypeEnum = exports.DiscoveryApi = void 0;
const runtime = __importStar(require("../runtime"));
const index_1 = require("../models/index");
/**
 *
 */
class DiscoveryApi extends runtime.BaseAPI {
    /**
     * Get Connection By Id And Type.
     */
    async discoveryConnectionByIdRaw(requestParameters, initOverrides) {
        if (requestParameters.connectionId === null || requestParameters.connectionId === undefined) {
            throw new runtime.RequiredError('connectionId', 'Required parameter requestParameters.connectionId was null or undefined when calling discoveryConnectionById.');
        }
        const queryParameters = {};
        if (requestParameters.connectionId !== undefined) {
            queryParameters['connectionId'] = requestParameters.connectionId;
        }
        if (requestParameters.type !== undefined) {
            queryParameters['type'] = requestParameters.type;
        }
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/discovery/connectionbyid`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.VoidApiResponse(response);
    }
    /**
     * Get Connection By Id And Type.
     */
    async discoveryConnectionById(requestParameters, initOverrides) {
        await this.discoveryConnectionByIdRaw(requestParameters, initOverrides);
    }
    /**
     * List Connections.
     */
    async discoveryConnectionsRaw(requestParameters, initOverrides) {
        const queryParameters = {};
        if (requestParameters.name !== undefined) {
            queryParameters['name'] = requestParameters.name;
        }
        if (requestParameters.region !== undefined) {
            queryParameters['region'] = requestParameters.region;
        }
        if (requestParameters.type !== undefined) {
            queryParameters['type'] = requestParameters.type;
        }
        if (requestParameters.page !== undefined) {
            queryParameters['page'] = requestParameters.page;
        }
        if (requestParameters.pageSize !== undefined) {
            queryParameters['pageSize'] = requestParameters.pageSize;
        }
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/discovery/connections`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.VoidApiResponse(response);
    }
    /**
     * List Connections.
     */
    async discoveryConnections(requestParameters = {}, initOverrides) {
        await this.discoveryConnectionsRaw(requestParameters, initOverrides);
    }
    /**
     * Creates New Connection.
     */
    async discoveryCreateConnectionRaw(requestParameters, initOverrides) {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model', 'Required parameter requestParameters.model was null or undefined when calling discoveryCreateConnection.');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/discovery/createconnection`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: (0, index_1.DiscoveryConnectionsViewModelToJSON)(requestParameters.model),
        }, initOverrides);
        return new runtime.VoidApiResponse(response);
    }
    /**
     * Creates New Connection.
     */
    async discoveryCreateConnection(requestParameters, initOverrides) {
        await this.discoveryCreateConnectionRaw(requestParameters, initOverrides);
    }
    /**
     * Deletes Connection.
     */
    async discoveryDeleteConnectionRaw(requestParameters, initOverrides) {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model', 'Required parameter requestParameters.model was null or undefined when calling discoveryDeleteConnection.');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/discovery/deleteconnection`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: (0, index_1.DeleteDiscoveryConnectionModelToJSON)(requestParameters.model),
        }, initOverrides);
        return new runtime.VoidApiResponse(response);
    }
    /**
     * Deletes Connection.
     */
    async discoveryDeleteConnection(requestParameters, initOverrides) {
        await this.discoveryDeleteConnectionRaw(requestParameters, initOverrides);
    }
    /**
     * Edits Connection.
     */
    async discoveryEditConnectionRaw(requestParameters, initOverrides) {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model', 'Required parameter requestParameters.model was null or undefined when calling discoveryEditConnection.');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/discovery/editconnection`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: (0, index_1.DiscoveryConnectionsViewModelToJSON)(requestParameters.model),
        }, initOverrides);
        return new runtime.VoidApiResponse(response);
    }
    /**
     * Edits Connection.
     */
    async discoveryEditConnection(requestParameters, initOverrides) {
        await this.discoveryEditConnectionRaw(requestParameters, initOverrides);
    }
    /**
     * Returns exclude operation result.  This operation note override existing data, append to existing data.  If you want to override please use update-settings endpoint.
     */
    async discoveryExcludeRaw(requestParameters, initOverrides) {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model', 'Required parameter requestParameters.model was null or undefined when calling discoveryExclude.');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/discovery/exclude`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: (0, index_1.ExcludeFilterToJSON)(requestParameters.model),
        }, initOverrides);
        return new runtime.JSONApiResponse(response);
    }
    /**
     * Returns exclude operation result.  This operation note override existing data, append to existing data.  If you want to override please use update-settings endpoint.
     */
    async discoveryExclude(requestParameters, initOverrides) {
        const response = await this.discoveryExcludeRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Returns the all discovery services in the csv format as a downloadable file.
     */
    async discoveryExportRaw(requestParameters, initOverrides) {
        const queryParameters = {};
        if (requestParameters.csvSeparator !== undefined) {
            queryParameters['csvSeparator'] = requestParameters.csvSeparator;
        }
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/discovery/export`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response);
    }
    /**
     * Returns the all discovery services in the csv format as a downloadable file.
     */
    async discoveryExport(requestParameters = {}, initOverrides) {
        const response = await this.discoveryExportRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Ignores discovery service with given service ids.
     */
    async discoveryIgnoreRaw(requestParameters, initOverrides) {
        if (requestParameters.serviceIds === null || requestParameters.serviceIds === undefined) {
            throw new runtime.RequiredError('serviceIds', 'Required parameter requestParameters.serviceIds was null or undefined when calling discoveryIgnore.');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/discovery/ignore`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: requestParameters.serviceIds,
        }, initOverrides);
        if (this.isJsonMime(response.headers.get('content-type'))) {
            return new runtime.JSONApiResponse(response);
        }
        else {
            return new runtime.TextApiResponse(response);
        }
    }
    /**
     * Ignores discovery service with given service ids.
     */
    async discoveryIgnore(requestParameters, initOverrides) {
        const response = await this.discoveryIgnoreRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Ignores discovery services for selected filters.
     */
    async discoveryIgnoreByFilterRaw(requestParameters, initOverrides) {
        const queryParameters = {};
        if (requestParameters.authority !== undefined) {
            queryParameters['authority'] = requestParameters.authority;
        }
        if (requestParameters.ipAddress !== undefined) {
            queryParameters['ipAddress'] = requestParameters.ipAddress;
        }
        if (requestParameters.secondLevelDomain !== undefined) {
            queryParameters['secondLevelDomain'] = requestParameters.secondLevelDomain;
        }
        if (requestParameters.topLevelDomain !== undefined) {
            queryParameters['topLevelDomain'] = requestParameters.topLevelDomain;
        }
        if (requestParameters.organizationName !== undefined) {
            queryParameters['organizationName'] = requestParameters.organizationName;
        }
        if (requestParameters.distance !== undefined) {
            queryParameters['distance'] = requestParameters.distance;
        }
        if (requestParameters.registeredDomain !== undefined) {
            queryParameters['registeredDomain'] = requestParameters.registeredDomain;
        }
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/discovery/ignorebyfilter`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        if (this.isJsonMime(response.headers.get('content-type'))) {
            return new runtime.JSONApiResponse(response);
        }
        else {
            return new runtime.TextApiResponse(response);
        }
    }
    /**
     * Ignores discovery services for selected filters.
     */
    async discoveryIgnoreByFilter(requestParameters = {}, initOverrides) {
        const response = await this.discoveryIgnoreByFilterRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Gets the list discovery services.
     */
    async discoveryListRaw(requestParameters, initOverrides) {
        const queryParameters = {};
        if (requestParameters.page !== undefined) {
            queryParameters['page'] = requestParameters.page;
        }
        if (requestParameters.pageSize !== undefined) {
            queryParameters['pageSize'] = requestParameters.pageSize;
        }
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/discovery/list`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => (0, index_1.DiscoveryServiceListApiResultFromJSON)(jsonValue));
    }
    /**
     * Gets the list discovery services.
     */
    async discoveryList(requestParameters = {}, initOverrides) {
        const response = await this.discoveryListRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Gets the list discovery services with filter.
     */
    async discoveryListByFilterRaw(requestParameters, initOverrides) {
        const queryParameters = {};
        if (requestParameters.authority !== undefined) {
            queryParameters['authority'] = requestParameters.authority;
        }
        if (requestParameters.ipAddress !== undefined) {
            queryParameters['ipAddress'] = requestParameters.ipAddress;
        }
        if (requestParameters.secondLevelDomain !== undefined) {
            queryParameters['secondLevelDomain'] = requestParameters.secondLevelDomain;
        }
        if (requestParameters.topLevelDomain !== undefined) {
            queryParameters['topLevelDomain'] = requestParameters.topLevelDomain;
        }
        if (requestParameters.organizationName !== undefined) {
            queryParameters['organizationName'] = requestParameters.organizationName;
        }
        if (requestParameters.distance !== undefined) {
            queryParameters['distance'] = requestParameters.distance;
        }
        if (requestParameters.registeredDomain !== undefined) {
            queryParameters['registeredDomain'] = requestParameters.registeredDomain;
        }
        if (requestParameters.status !== undefined) {
            queryParameters['status'] = requestParameters.status;
        }
        if (requestParameters.page !== undefined) {
            queryParameters['page'] = requestParameters.page;
        }
        if (requestParameters.pageSize !== undefined) {
            queryParameters['pageSize'] = requestParameters.pageSize;
        }
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/discovery/listbyfilter`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => (0, index_1.DiscoveryServiceListApiResultFromJSON)(jsonValue));
    }
    /**
     * Gets the list discovery services with filter.
     */
    async discoveryListByFilter(requestParameters = {}, initOverrides) {
        const response = await this.discoveryListByFilterRaw(requestParameters, initOverrides);
        return await response.value();
    }
    /**
     * Gets the discovery settings.
     */
    async discoverySettingsRaw(initOverrides) {
        const queryParameters = {};
        const headerParameters = {};
        const response = await this.request({
            path: `/api/1.0/discovery/settings`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => (0, index_1.DiscoverySettingsApiModelFromJSON)(jsonValue));
    }
    /**
     * Gets the discovery settings.
     */
    async discoverySettings(initOverrides) {
        const response = await this.discoverySettingsRaw(initOverrides);
        return await response.value();
    }
    /**
     * Updates discovery settings.
     */
    async discoveryUpdateSettingsRaw(requestParameters, initOverrides) {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model', 'Required parameter requestParameters.model was null or undefined when calling discoveryUpdateSettings.');
        }
        const queryParameters = {};
        const headerParameters = {};
        headerParameters['Content-Type'] = 'application/json';
        const response = await this.request({
            path: `/api/1.0/discovery/update-settings`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: (0, index_1.DiscoverySettingsApiModelToJSON)(requestParameters.model),
        }, initOverrides);
        return new runtime.JSONApiResponse(response, (jsonValue) => (0, index_1.DiscoverySettingsApiModelFromJSON)(jsonValue));
    }
    /**
     * Updates discovery settings.
     */
    async discoveryUpdateSettings(requestParameters, initOverrides) {
        const response = await this.discoveryUpdateSettingsRaw(requestParameters, initOverrides);
        return await response.value();
    }
}
exports.DiscoveryApi = DiscoveryApi;
/**
 * @export
 */
exports.DiscoveryConnectionByIdTypeEnum = {
    Aws: 'Aws'
};
/**
 * @export
 */
exports.DiscoveryConnectionsTypeEnum = {
    Aws: 'Aws'
};
/**
 * @export
 */
exports.DiscoveryExportCsvSeparatorEnum = {
    Comma: 'Comma',
    Semicolon: 'Semicolon',
    Pipe: 'Pipe',
    Tab: 'Tab'
};
/**
 * @export
 */
exports.DiscoveryListByFilterStatusEnum = {
    Discovered: 'Discovered',
    Ignored: 'Ignored',
    Created: 'Created'
};
//# sourceMappingURL=DiscoveryApi.js.map