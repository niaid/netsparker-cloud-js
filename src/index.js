"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NetsparkerCloud = void 0;
class NetsparkerCloud {
    constructor(configuration, requestFactory) {
        this.configuration = configuration;
        this.requestFactory = requestFactory;
    }
    GetApi10AccountLicense() {
        const path = "/api/1.0/account/license";
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10AccountMe() {
        const path = "/api/1.0/account/me";
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10AgentgroupsDelete(body) {
        const path = "/api/1.0/agentgroups/delete";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10AgentgroupsList(query) {
        const path = "/api/1.0/agentgroups/list";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10AgentgroupsNew(body) {
        const path = "/api/1.0/agentgroups/new";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10AgentgroupsUpdate(body) {
        const path = "/api/1.0/agentgroups/update";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10AgentsDelete(body) {
        const path = "/api/1.0/agents/delete";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10AgentsList(query) {
        const path = "/api/1.0/agents/list";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10AgentsSetstatus(body) {
        const path = "/api/1.0/agents/setstatus";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10AuditlogsExport(query) {
        const path = "/api/1.0/auditlogs/export";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10AuthenticationprofilesDelete(body) {
        const path = "/api/1.0/authenticationprofiles/delete";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10AuthenticationprofilesGetById(idPathParameter) {
        let path = "/api/1.0/authenticationprofiles/get/{id}";
        path = path.replace("{id}", String(idPathParameter));
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10AuthenticationprofilesGetall() {
        const path = "/api/1.0/authenticationprofiles/getall";
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10AuthenticationprofilesNew(body) {
        const path = "/api/1.0/authenticationprofiles/new";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10AuthenticationprofilesUpdate(body) {
        const path = "/api/1.0/authenticationprofiles/update";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10DiscoveryExclude(body) {
        const path = "/api/1.0/discovery/exclude";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10DiscoveryExport(query) {
        const path = "/api/1.0/discovery/export";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10DiscoveryIgnore(body) {
        const path = "/api/1.0/discovery/ignore";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10DiscoveryIgnorebyfilter(query) {
        const path = "/api/1.0/discovery/ignorebyfilter";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10DiscoveryList(query) {
        const path = "/api/1.0/discovery/list";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10DiscoveryListbyfilter(query) {
        const path = "/api/1.0/discovery/listbyfilter";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10DiscoverySettings() {
        const path = "/api/1.0/discovery/settings";
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10DiscoveryUpdateSettings(body) {
        const path = "/api/1.0/discovery/update-settings";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10IssuesAddressedissues(query) {
        const path = "/api/1.0/issues/addressedissues";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10IssuesAllissues(query) {
        const path = "/api/1.0/issues/allissues";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10IssuesGetById(idPathParameter) {
        let path = "/api/1.0/issues/get/{id}";
        path = path.replace("{id}", String(idPathParameter));
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10IssuesGetvulnerabilitycontentById(idPathParameter) {
        let path = "/api/1.0/issues/getvulnerabilitycontent/{id}";
        path = path.replace("{id}", String(idPathParameter));
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10IssuesReport(query) {
        const path = "/api/1.0/issues/report";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10IssuesTodo(query) {
        const path = "/api/1.0/issues/todo";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10IssuesUpdate(body) {
        const path = "/api/1.0/issues/update";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10IssuesWaitingforretest(query) {
        const path = "/api/1.0/issues/waitingforretest";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10NotificationsDelete(body) {
        const path = "/api/1.0/notifications/delete";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10NotificationsGetById(idPathParameter) {
        let path = "/api/1.0/notifications/get/{id}";
        path = path.replace("{id}", String(idPathParameter));
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10NotificationsGetpriorities(query) {
        const path = "/api/1.0/notifications/getpriorities";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10NotificationsGetscangroups(query) {
        const path = "/api/1.0/notifications/getscangroups";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10NotificationsList(query) {
        const path = "/api/1.0/notifications/list";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10NotificationsNew(body) {
        const path = "/api/1.0/notifications/new";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10NotificationsSetpriorities(body) {
        const path = "/api/1.0/notifications/setpriorities";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10NotificationsUpdate(body) {
        const path = "/api/1.0/notifications/update";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScanpoliciesDelete(body) {
        const path = "/api/1.0/scanpolicies/delete";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10ScanpoliciesGet(query) {
        const path = "/api/1.0/scanpolicies/get";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10ScanpoliciesGetById(idPathParameter) {
        let path = "/api/1.0/scanpolicies/get/{id}";
        path = path.replace("{id}", String(idPathParameter));
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10ScanpoliciesList(query) {
        const path = "/api/1.0/scanpolicies/list";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10ScanpoliciesNew(body) {
        const path = "/api/1.0/scanpolicies/new";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScanpoliciesUpdate(body) {
        const path = "/api/1.0/scanpolicies/update";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScanprofilesDelete(body) {
        const path = "/api/1.0/scanprofiles/delete";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10ScanprofilesGet(query) {
        const path = "/api/1.0/scanprofiles/get";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10ScanprofilesGetById(idPathParameter) {
        let path = "/api/1.0/scanprofiles/get/{id}";
        path = path.replace("{id}", String(idPathParameter));
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10ScanprofilesList(query) {
        const path = "/api/1.0/scanprofiles/list";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10ScanprofilesNew(body) {
        const path = "/api/1.0/scanprofiles/new";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScanprofilesUpdate(body) {
        const path = "/api/1.0/scanprofiles/update";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScansCancel(body) {
        const path = "/api/1.0/scans/cancel";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10ScansCustomReport(query) {
        const path = "/api/1.0/scans/custom-report/";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10ScansDelete(body) {
        const path = "/api/1.0/scans/delete";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10ScansDetailById(idPathParameter) {
        let path = "/api/1.0/scans/detail/{id}";
        path = path.replace("{id}", String(idPathParameter));
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10ScansDownloadscanfile(query) {
        const path = "/api/1.0/scans/downloadscanfile";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10ScansIncremental(body) {
        const path = "/api/1.0/scans/incremental";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10ScansList(query) {
        const path = "/api/1.0/scans/list";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10ScansListbystate(query) {
        const path = "/api/1.0/scans/listbystate";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10ScansListbystatechanged(query) {
        const path = "/api/1.0/scans/listbystatechanged";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10ScansListbywebsite(query) {
        const path = "/api/1.0/scans/listbywebsite";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10ScansListScheduled(query) {
        const path = "/api/1.0/scans/list-scheduled";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10ScansNew(body) {
        const path = "/api/1.0/scans/new";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScansNewfromscan(body) {
        const path = "/api/1.0/scans/newfromscan";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScansNewgroupscan(body) {
        const path = "/api/1.0/scans/newgroupscan";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScansNewwithprofile(body) {
        const path = "/api/1.0/scans/newwithprofile";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScansPause(body) {
        const path = "/api/1.0/scans/pause";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10ScansReport(query) {
        const path = "/api/1.0/scans/report/";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10ScansResultById(idPathParameter) {
        let path = "/api/1.0/scans/result/{id}";
        path = path.replace("{id}", String(idPathParameter));
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10ScansResume(body) {
        const path = "/api/1.0/scans/resume";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScansRetest(body) {
        const path = "/api/1.0/scans/retest";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScansSchedule(body) {
        const path = "/api/1.0/scans/schedule";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScansScheduleIncremental(body) {
        const path = "/api/1.0/scans/schedule-incremental";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScansSchedulewithprofile(body) {
        const path = "/api/1.0/scans/schedulewithprofile";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10ScansStatusById(idPathParameter) {
        let path = "/api/1.0/scans/status/{id}";
        path = path.replace("{id}", String(idPathParameter));
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10ScansTestScanProfileCredentials(body) {
        const path = "/api/1.0/scans/test-scan-profile-credentials";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScansUnschedule(body) {
        const path = "/api/1.0/scans/unschedule";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScansUpdateScheduled(body) {
        const path = "/api/1.0/scans/update-scheduled";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScansUpdateScheduledIncremental(body) {
        const path = "/api/1.0/scans/update-scheduled-incremental";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10ScansVerifyformauth(body) {
        const path = "/api/1.0/scans/verifyformauth";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10TeammembersDeleteById(idPathParameter) {
        let path = "/api/1.0/teammembers/delete/{id}";
        path = path.replace("{id}", String(idPathParameter));
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "POST", this.configuration);
    }
    GetApi10TeammembersGetById(idPathParameter) {
        let path = "/api/1.0/teammembers/get/{id}";
        path = path.replace("{id}", String(idPathParameter));
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10TeammembersGetapitoken(query) {
        const path = "/api/1.0/teammembers/getapitoken";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10TeammembersGetbyemail(query) {
        const path = "/api/1.0/teammembers/getbyemail";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10TeammembersGettimezones() {
        const path = "/api/1.0/teammembers/gettimezones";
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10TeammembersList(query) {
        const path = "/api/1.0/teammembers/list";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10TeammembersNew(body) {
        const path = "/api/1.0/teammembers/new";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10TeammembersUpdate(body) {
        const path = "/api/1.0/teammembers/update";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10TechnologiesList(query) {
        const path = "/api/1.0/technologies/list";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10TechnologiesOutofdatetechnologies(query) {
        const path = "/api/1.0/technologies/outofdatetechnologies";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10VulnerabilityList(query) {
        const path = "/api/1.0/vulnerability/list";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10VulnerabilityTemplate(query) {
        const path = "/api/1.0/vulnerability/template";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10VulnerabilityTypes() {
        const path = "/api/1.0/vulnerability/types";
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10WebsitegroupsDelete(body) {
        const path = "/api/1.0/websitegroups/delete";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10WebsitegroupsDeleteById(idPathParameter) {
        let path = "/api/1.0/websitegroups/delete/{id}";
        path = path.replace("{id}", String(idPathParameter));
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "POST", this.configuration);
    }
    GetApi10WebsitegroupsGet(query) {
        const path = "/api/1.0/websitegroups/get";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10WebsitegroupsGetById(idPathParameter) {
        let path = "/api/1.0/websitegroups/get/{id}";
        path = path.replace("{id}", String(idPathParameter));
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10WebsitegroupsList(query) {
        const path = "/api/1.0/websitegroups/list";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10WebsitegroupsNew(body) {
        const path = "/api/1.0/websitegroups/new";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10WebsitegroupsUpdate(body) {
        const path = "/api/1.0/websitegroups/update";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10WebsitesDelete(body) {
        const path = "/api/1.0/websites/delete";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10WebsitesGet(query) {
        const path = "/api/1.0/websites/get";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10WebsitesGetById(idPathParameter) {
        let path = "/api/1.0/websites/get/{id}";
        path = path.replace("{id}", String(idPathParameter));
        return this.requestFactory(path, undefined, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10WebsitesGetwebsitesbygroup(query) {
        const path = "/api/1.0/websites/getwebsitesbygroup";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    GetApi10WebsitesList(query) {
        const path = "/api/1.0/websites/list";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10WebsitesNew(body) {
        const path = "/api/1.0/websites/new";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10WebsitesSendverificationemail(body) {
        const path = "/api/1.0/websites/sendverificationemail";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10WebsitesStartverification(body) {
        const path = "/api/1.0/websites/startverification";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    PostApi10WebsitesUpdate(body) {
        const path = "/api/1.0/websites/update";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
    GetApi10WebsitesVerificationfile(query) {
        const path = "/api/1.0/websites/verificationfile";
        return this.requestFactory(path, query, undefined, undefined, undefined, "GET", this.configuration);
    }
    PostApi10WebsitesVerify(body) {
        const path = "/api/1.0/websites/verify";
        return this.requestFactory(path, undefined, body, undefined, undefined, "POST", this.configuration);
    }
}
exports.NetsparkerCloud = NetsparkerCloud;
//# sourceMappingURL=index.js.map