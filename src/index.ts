export type AccountLicenseApiModel = {
  SubscriptionMaximumSiteLimit?: number;
  SubscriptionSiteCount?: number;
  SubscriptionEndDate?: string;
  SubscriptionStartDate?: string;
  IsAccountWhitelisted?: boolean;
  UsedScanCreditCount?: number;
  ScanCreditCount?: number;
  IsCreditScanEnabled?: boolean;
  IsSubscriptionEnabled?: boolean;
  PreVerifiedWebsites?: Array<string>;
  Licenses?: Array<LicenseBaseModel>;
};

export type LicenseBaseModel = {
  Id?: string;
  IsActive?: boolean;
  Key?: string;
  AccountCanCreateSharkScanTask?: boolean;
};

export type UserHealthCheckApiModel = {
  DateFormat?: string;
  DisplayName?: string;
  Email?: string;
  TimeZoneInfo?: string;
};

export type AgentGroupApiDeleteModel = {
  Name: string;
};

export type AgentGroupsListApiResult = {
  FirstItemOnPage?: number;
  HasNextPage?: boolean;
  HasPreviousPage?: boolean;
  IsFirstPage?: boolean;
  IsLastPage?: boolean;
  LastItemOnPage?: number;
  List?: Array<AgentGroupApiModel>;
  PageCount?: number;
  PageNumber?: number;
  PageSize?: number;
  TotalItemCount?: number;
};

export type AgentGroupApiModel = {
  Agents?: Array<string>;
  Id?: string;
  Name?: string;
};

export type AgentGroupApiNewModel = {
  Agents: Array<string>;
  Name?: string;
};

export type AgentGroupModel = {
  Agents?: Array<string>;
  Id?: string;
  Name?: string;
};

export type AgentGroupApiUpdateModel = {
  Agents: Array<string>;
  Id?: string;
  Name?: string;
};

export type AgentListApiResult = {
  FirstItemOnPage?: number;
  HasNextPage?: boolean;
  HasPreviousPage?: boolean;
  IsFirstPage?: boolean;
  IsLastPage?: boolean;
  LastItemOnPage?: number;
  List?: Array<AgentListApiModel>;
  PageCount?: number;
  PageNumber?: number;
  PageSize?: number;
  TotalItemCount?: number;
};

export type AgentListApiModel = {
  Id?: string;
  Heartbeat?: string;
  IpAddress?: string;
  Launched?: string;
  Name?: string;
  State?: string;
  Version?: string;
  AutoUpdateEnabled?: boolean;
  HasWaitingCommand?: boolean;
  VdbVersion?: string;
  OsDescription?: string;
  FrameworkDescription?: string;
  OsArchitecture?: string;
  ProcessArchitecture?: string;
  IsAgentNeedsUpdate?: boolean;
};

export type AgentStatusModel = {
  AgentId: string;
  Status?: boolean;
};

export type DeleteAgentModel = {
  AgentId: string;
};

export type AuthenticationProfileViewModel = {
  id?: string;
  name: string;
  triggeredUrl?: string;
  loginUrl?: string;
  customScripts?: Array<CustomScriptPageViewModel>;
};

export type CustomScriptPageViewModel = {
  key: string;
  value?: string;
};

export type DiscoveryServiceListApiResult = {
  FirstItemOnPage?: number;
  HasNextPage?: boolean;
  HasPreviousPage?: boolean;
  IsFirstPage?: boolean;
  IsLastPage?: boolean;
  LastItemOnPage?: number;
  List?: Array<DiscoveryApiModel>;
  PageCount?: number;
  PageNumber?: number;
  PageSize?: number;
  TotalItemCount?: number;
};

export type DiscoveryApiModel = {
  Id?: string;
  SubDomain?: string;
  SecondLevelDomain?: string;
  SecondLevelDomainCount?: number;
  TopLevelDomain?: string;
  TopLevelDomainCount?: number;
  Authority?: string;
  Https?: boolean;
  IpAddress?: string;
  IpAddressCount?: number;
  OrganizationName?: string;
  OrganizationNameCount?: number;
  Copyright?: string;
  AccountId?: string;
  WebsiteId?: string;
  WebsiteName?: string;
  Distance?: number;
  Status?: string;
};

export type File = {};

export type DiscoverySettingsApiModel = {
  IncludedSlds?: string;
  IncludedIpRanges?: string;
  IncludedOrganizations?: string;
  ExcludedSlds?: string;
  ExcludedTlds?: string;
  ExcludedIpAddresses?: string;
  ExcludedOrganizations?: string;
  OnlyRegisteredDomains?: boolean;
  SharedHostMatching?: boolean;
  OrganizationNameMatching?: boolean;
  EmailMatching?: boolean;
  WebsitesMatching?: boolean;
};

export type ExcludeFilter = {
  ExcludedSlds?: Array<string>;
  ExcludedTlds?: Array<string>;
  ExcludedIpAddresses?: Array<string>;
  ExcludedDomains?: Array<string>;
  ExcludedOrganizations?: Array<string>;
};

export type IssueApiResult = {
  FirstItemOnPage?: number;
  HasNextPage?: boolean;
  HasPreviousPage?: boolean;
  IsFirstPage?: boolean;
  IsLastPage?: boolean;
  LastItemOnPage?: number;
  List?: Array<IssueApiModel>;
  PageCount?: number;
  PageNumber?: number;
  PageSize?: number;
  TotalItemCount?: number;
};

export type IssueApiModel = {
  AssigneeName?: string;
  FirstSeenDate?: string;
  Id?: string;
  IsAddressed?: boolean;
  IsDetectedByShark?: boolean;
  IsPresent?: boolean;
  LastSeenDate?: string;
  Severity?: string;
  State?: string;
  Title?: string;
  Url?: string;
  LatestVulnerabilityIsConfirmed?: boolean;
  WebsiteId?: string;
  WebsiteName?: string;
  WebsiteRootUrl?: string;
  FixTimeInMinutes?: number;
  Certainty?: number;
  Parameters?: Array<IssueRequestContentParametersApiModel>;
  VulnerabilityDetail?: string;
  Impact?: string;
  Actions?: string;
  Skills?: string;
  Remedy?: string;
  RemedyReferences?: string;
  ExternalReferences?: string;
  ProofOfConcept?: string;
  CustomData?: string;
  CustomFields?: Array<CustomFieldModel>;
  ClassificationLinks?: Array<string>;
  CvssVectorString?: string;
  Cvss31VectorString?: string;
  Type?: string;
  Classification?: VulnerabilityClassification;
  CvssVector?: {
    Base?: CvssMetricModel;
    Temporal?: CvssMetricModel;
    Environmental?: CvssMetricModel;
  };
  VersionIssues?: Array<VersionIssue>;
  IsRetest?: boolean;
  IsTodo?: boolean;
  LatestScanId?: string;
  History?: Array<IssueHistoryApiModel>;
  Tags?: Array<string>;
};

export type IssueRequestContentParametersApiModel = {
  Name?: string;
  Value?: string;
  TypeName?: string;
  InputType?: string;
};

export type CustomFieldModel = {
  Name?: string;
  Values?: Array<string>;
};

export type VulnerabilityClassification = {
  Asvs40?: string;
  Capec?: string;
  Cwe?: string;
  DisaStig?: string;
  Hipaa?: string;
  IsEmpty?: boolean;
  Iso27001?: string;
  Nistsp80053?: string;
  Owasp2013?: string;
  Owasp2017?: string;
  OwaspProactiveControls?: string;
  Pci32?: string;
  Wasc?: string;
};

export type CvssMetricModel = {
  Score?: CvssScoreValue;
  Metrics?: { [key: string]: string };
};

export type VersionIssue = {
  Exploit?: string;
  ExternalReferences?: string;
  FromVersionOrdinal?: number;
  FromVersion?: string;
  Id?: number;
  Impact?: string;
  Remedy?: string;
  Severity?: string;
  Summary?: string;
  Title?: string;
  ToVersionOrdinal?: number;
  ToVersion?: string;
  Vulnerability?: string;
  Application?: number;
  Bdu?: string;
};

export type IssueHistoryApiModel = {
  Message?: string;
  Note?: string;
  Owner?: string;
  Date?: string;
};

export type CvssScoreValue = {
  Severity?: string;
  Value?: number;
};

export type IssueApiUpdateModel = {
  IssueId?: string;
  State?: string;
  AssigneeId?: string;
  Note?: string;
  Tags?: Array<string>;
};

export type VulnerabilityContentApiModel = {
  RequestContent?: string;
  ResponseContent?: string;
  InjectionContent?: string;
  ResponseDuration?: number;
};

export type IssueReportFilterApiModel = {
  CsvSeparator?: string;
  Severity?: string;
  WebsiteGroupName?: string;
  WebSiteName?: string;
};

export type DeleteScanNotificationApiModel = {
  Id: string;
};

export type ScanNotificationApiModel = {
  Id?: string;
  Priority?: number;
  Recipients?: ScanNotificationRecipientApiModel;
  WebsiteGroupName?: string;
  WebsiteRootUrl?: string;
  Certainty?: number;
  Disabled: boolean;
  ScanTaskGroupId?: string;
  Event?: string;
  IsConfirmed?: boolean;
  Severity?: string;
  State?: string;
  Name?: string;
  Scope?: string;
};

export type ScanNotificationRecipientApiModel = {
  OutsiderRecipients?: Array<OutsiderRecipient>;
  EmailRecipientUsers?: Array<ScanNotificationRecipientUserApiModel>;
  ExcludedUsers?: Array<ScanNotificationRecipientUserApiModel>;
  IntegrationRecipients?: Array<string>;
  SmsRecipientUsers?: Array<ScanNotificationRecipientUserApiModel>;
  SpecificEmailRecipients?: Array<string>;
  SpecificSmsRecipients?: Array<string>;
};

export type OutsiderRecipient = {
  Email?: string;
};

export type ScanNotificationRecipientUserApiModel = {
  Email?: string;
  Name?: string;
  PhoneNumber?: string;
};

export type ScanNotificationScanTaskGroupApiModel = {
  WebsiteId?: string;
  ScanTaskGroupName?: string;
  ScanTaskGroupId?: string;
};

export type ScanNotificationListApiResult = {
  FirstItemOnPage?: number;
  HasNextPage?: boolean;
  HasPreviousPage?: boolean;
  IsFirstPage?: boolean;
  IsLastPage?: boolean;
  LastItemOnPage?: number;
  List?: Array<ScanNotificationApiModel>;
  PageCount?: number;
  PageNumber?: number;
  PageSize?: number;
  TotalItemCount?: number;
};

export type NewScanNotificationApiModel = {
  Recipients: NewScanNotificationRecipientApiModel;
  WebsiteGroupName?: string;
  WebsiteRootUrl?: string;
  Certainty?: number;
  Disabled?: boolean;
  ScanTaskGroupId?: string;
  Event?: string;
  IsConfirmed?: boolean;
  Severity?: string;
  State?: string;
  Name?: string;
  Scope?: string;
};

export type NewScanNotificationRecipientApiModel = {
  Emails?: Array<string>;
  ExcludedUsers?: Array<string>;
  Integrations?: Array<string>;
  PhoneNumbers?: Array<string>;
  OutsiderRecipients?: Array<string>;
  SpecificEmailRecipients?: Array<string>;
  SpecificSmsRecipients?: Array<string>;
};

export type NotificationPriorityPair = {
  Id?: string;
  Priority?: number;
};

export type UpdateScanNotificationApiModel = {
  Id: string;
  Recipients?: NewScanNotificationRecipientApiModel;
  WebsiteGroupName?: string;
  WebsiteRootUrl?: string;
  Certainty?: number;
  Disabled?: boolean;
  ScanTaskGroupId?: string;
  Event?: string;
  IsConfirmed?: boolean;
  Severity?: string;
  State?: string;
  Name?: string;
  Scope?: string;
};

export type ScanPolicySettingApiModel = {
  IsReadonly?: boolean;
  Id?: string;
  IsShared?: boolean;
  DesktopId?: string;
  AttackingSettings: AttackingSettingModel;
  AutoCompleteSettings?: Array<AutoCompleteSettingModel>;
  BruteForceSettings?: BruteForceSettingModel;
  CrawlingSettings?: CrawlingSettingModel;
  CsrfSettings?: CsrfSettingModel;
  Custom404Settings?: Custom404SettingModel;
  CustomHttpHeaderSettings?: Array<CustomHttpHeaderSetting>;
  Description?: string;
  EnableKnowledgebase?: boolean;
  FormValueSettings?: Array<FormValueSettingModel>;
  HttpRequestSettings?: HttpRequestSettingModel;
  IgnoredEmailPatterns?: Array<EmailPatternSetting>;
  IgnorePatternSettings?: Array<IgnorePatternSettingModel>;
  JavaScriptSettings?: JavaScriptSettingsModel;
  Name?: string;
  ProxySettings?: ProxySettingsModel;
  ScopeSettings?: ScopeSettingModel;
  SecurityCheckGroupParents?: Array<SecurityCheckGroupParentModel>;
  SelectedGroups?: Array<string>;
  SensitiveKeywordSettings?: Array<SensitiveKeywordSettingModel>;
  SslTlsSettingModel?: SslTlsSettingModel;
  WebStorageSettings?: Array<WebStorageSetting>;
  ExtensionSettings?: Array<ExtensionSettingModel>;
  ResourceFinders?: Array<string>;
  ClonedScanPolicySettingId?: string;
};

export type AttackingSettingModel = {
  AntiCsrfTokenNames?: string;
  AttackParameterName?: boolean;
  AttackRefererHeader?: boolean;
  AttackUserAgentHeader?: boolean;
  AttackCookies?: boolean;
  MaxParametersToAttack?: number;
  OptimizeAttacksToRecurringParameters?: boolean;
  OptimizeHeaderAttacks?: boolean;
  ProofGenerationEnabled?: boolean;
  RecurringParametersPageAttackLimit?: number;
  UseExtraParameters?: boolean;
};

export type AutoCompleteSettingModel = {
  Value: string;
};

export type BruteForceSettingModel = {
  EnableAuthBruteForce?: boolean;
  MaxBruteForce?: number;
};

export type CrawlingSettingModel = {
  EnableParameterBasedNavigation?: boolean;
  EnableRestWebServiceParser?: boolean;
  EnableSoapWebServiceParser?: boolean;
  EnableTextParser?: boolean;
  FallbackToGet?: boolean;
  EnableFragmentParsing?: boolean;
  FileExtensions?: string;
  MaximumCrawlerUrlCount?: number;
  MaximumSignature?: number;
  NavigationParameterPageVisitLimit?: number;
  NavigationParameterRegexPattern?: string;
  PageVisitLimit?: number;
  MaximumUrlRewriteSignature?: number;
  WaitResourceFinder?: boolean;
  AddRelatedLinks?: boolean;
  EnableQueryBasedParameterBasedNavigation?: boolean;
};

export type CsrfSettingModel = {
  CaptchaIndicators?: string;
  LoginFormValues?: string;
  NonFormValues?: string;
  NonInputValues?: string;
  UserNameInputs?: string;
};

export type Custom404SettingModel = {
  Custom404RegEx?: string;
  DisableAuto404Detection?: boolean;
  Max404PagesToTest: number;
  Maximum404Signature?: number;
};

export type CustomHttpHeaderSetting = {
  AttackMode?: string;
  Enabled?: boolean;
  Name: string;
  Value?: string;
};

export type FormValueSettingModel = {
  Force?: boolean;
  Match?: string;
  MatchTarget?: Array<string>;
  MatchTargetValue: string;
  Name?: string;
  Pattern?: string;
  Type?: string;
  Value?: string;
};

export type HttpRequestSettingModel = {
  Accept?: string;
  AcceptCharset?: string;
  AcceptLanguage?: string;
  EnableCookies?: boolean;
  EnableGzipAndDeflate?: boolean;
  HttpKeepAlive?: boolean;
  LogHttpRequests?: boolean;
  RequestsPerSecond?: number;
  ConcurrentConnectionCount?: number;
  RequestTimeout?: number;
  UserAgent?: string;
  UserAgents?: { [key: string]: string };
  ForceUserAgent?: boolean;
};

export type EmailPatternSetting = {
  Value: string;
};

export type IgnorePatternSettingModel = {
  Name: string;
  ParameterType?: string;
  Pattern?: string;
};

export type JavaScriptSettingsModel = {
  BailThreshold?: number;
  ConfirmOpenRedirectSimulateTimeout?: number;
  ConfirmXssSimulateTimeout?: number;
  DomParserAllowOutOfScopeXmlHttpRequests?: boolean;
  DomParserDfsLimit?: number;
  DomParserDotify?: boolean;
  DomParserExclusionCssSelector?: string;
  DomParserExtractResources?: boolean;
  DomParserFilterColonEvents?: boolean;
  DomParserFilterDocumentEvents?: boolean;
  DomParserIgnoreDocumentEvents?: boolean;
  DomParserLoadUrlTimeout?: number;
  DomParserMaxOptionElementsPerSelect?: number;
  DomParserPersistentJavaScriptCookies?: string;
  DomParserPreSimulateWait?: number;
  DomParserSimulationTimeout?: number;
  EnableDomParser?: boolean;
  IntereventTimeout?: number;
  SkipElementCount?: number;
  SkipThreshold?: number;
};

export type ProxySettingsModel = {
  EnableCustomProxy?: boolean;
  ProxyAddress?: string;
  ProxyAuthenticationRequired?: boolean;
  ProxyDomain?: string;
  ProxyPassword?: string;
  ProxyPort?: number;
  ProxyUsername?: string;
};

export type ScopeSettingModel = {
  BlockAdNetworks?: boolean;
  ByPassScopeForStaticChecks?: boolean;
  CaseSensitiveScope?: boolean;
  ContentTypeCheckEnabled?: boolean;
  IgnoredContentTypes?: Array<ContentTypeModel>;
  RestrictedExtensions?: string;
};

export type SecurityCheckGroupParentModel = {
  Title?: string;
  SecurityCheckGroups?: Array<SecurityCheckGroupModel>;
};

export type SensitiveKeywordSettingModel = {
  Pattern: string;
};

export type SslTlsSettingModel = {
  ExternalDomainInvalidCertificateAction?: string;
  Ssl3Enabled?: boolean;
  TargetUrlInvalidCertificateAction?: string;
  Tls10Enabled?: boolean;
  Tls11Enabled?: boolean;
  Tls12Enabled?: boolean;
};

export type WebStorageSetting = {
  Key: string;
  Origin?: string;
  Type?: string;
  Value?: string;
};

export type ExtensionSettingModel = {
  AttackOption: string;
  CrawlOption?: string;
  Extension?: string;
};

export type ContentTypeModel = {
  Value: string;
};

export type SecurityCheckGroupModel = {
  Patterns?: Array<ScanPolicyPatternModel>;
  Settings?: Array<SecurityCheckSetting>;
  Type?: string;
  EngineGroup?: string;
  Description?: string;
  Enabled?: boolean;
  Id?: string;
  Name?: string;
};

export type ScanPolicyPatternModel = {
  CustomScriptId?: string;
  Description?: string;
  Enabled?: boolean;
  Id?: string;
  Name?: string;
};

export type SecurityCheckSetting = {
  Name?: string;
  Value?: string;
};

export type ScanPolicyListApiResult = {
  FirstItemOnPage?: number;
  HasNextPage?: boolean;
  HasPreviousPage?: boolean;
  IsFirstPage?: boolean;
  IsLastPage?: boolean;
  LastItemOnPage?: number;
  List?: Array<ScanPolicySettingItemApiModel>;
  PageCount?: number;
  PageNumber?: number;
  PageSize?: number;
  TotalItemCount?: number;
};

export type ScanPolicySettingItemApiModel = {
  Description?: string;
  Groups?: Array<WebsiteGroupModel>;
  Id?: string;
  IsDefault?: boolean;
  IsShared?: boolean;
  Name?: string;
  OptimizerOptions?: ScanPolicyOptimizerOptions;
};

export type WebsiteGroupModel = {
  DisplayName?: string;
  Id?: string;
  Name?: string;
  NotVerifiedWebsiteCount?: number;
  VerifiedWebsiteCount?: number;
};

export type ScanPolicyOptimizerOptions = {
  AppServer?: string;
  DatabaseServer?: string;
  DirectoryNameLimit?: number;
  DomParserPreset?: string;
  Hosts?: Array<string>;
  Name?: string;
  NetsparkerHawkBaseUrl?: string;
  OperatingSystem?: string;
  Optimized?: boolean;
  ResourceFinders?: Array<string>;
  SuggestionStatus?: string;
  WebServer?: string;
};

export type NewScanPolicySettingModel = {
  DesktopId?: string;
  AttackingSettings: AttackingSettingModel;
  AutoCompleteSettings?: Array<AutoCompleteSettingModel>;
  BruteForceSettings?: BruteForceSettingModel;
  CrawlingSettings?: CrawlingSettingModel;
  CsrfSettings?: CsrfSettingModel;
  Custom404Settings?: Custom404SettingModel;
  CustomHttpHeaderSettings?: Array<CustomHttpHeaderSetting>;
  Description?: string;
  EnableKnowledgebase?: boolean;
  FormValueSettings?: Array<FormValueSettingModel>;
  HttpRequestSettings?: HttpRequestSettingModel;
  IgnoredEmailPatterns?: Array<EmailPatternSetting>;
  IgnorePatternSettings?: Array<IgnorePatternSettingModel>;
  IsShared?: boolean;
  JavaScriptSettings?: JavaScriptSettingsModel;
  Name?: string;
  ProxySettings?: ProxySettingsModel;
  ScopeSettings?: ScopeSettingModel;
  SecurityCheckGroupParents?: Array<SecurityCheckGroupParentModel>;
  SelectedGroups?: Array<string>;
  SensitiveKeywordSettings?: Array<SensitiveKeywordSettingModel>;
  SslTlsSettingModel?: SslTlsSettingModel;
  WebStorageSettings?: Array<WebStorageSetting>;
  ExtensionSettings?: Array<ExtensionSettingModel>;
  ResourceFinders?: Array<string>;
  ClonedScanPolicySettingId?: string;
};

export type UpdateScanPolicySettingModel = {
  Id?: string;
  IsShared?: boolean;
  DesktopId?: string;
  AttackingSettings: AttackingSettingModel;
  AutoCompleteSettings?: Array<AutoCompleteSettingModel>;
  BruteForceSettings?: BruteForceSettingModel;
  CrawlingSettings?: CrawlingSettingModel;
  CsrfSettings?: CsrfSettingModel;
  Custom404Settings?: Custom404SettingModel;
  CustomHttpHeaderSettings?: Array<CustomHttpHeaderSetting>;
  Description?: string;
  EnableKnowledgebase?: boolean;
  FormValueSettings?: Array<FormValueSettingModel>;
  HttpRequestSettings?: HttpRequestSettingModel;
  IgnoredEmailPatterns?: Array<EmailPatternSetting>;
  IgnorePatternSettings?: Array<IgnorePatternSettingModel>;
  JavaScriptSettings?: JavaScriptSettingsModel;
  Name?: string;
  ProxySettings?: ProxySettingsModel;
  ScopeSettings?: ScopeSettingModel;
  SecurityCheckGroupParents?: Array<SecurityCheckGroupParentModel>;
  SelectedGroups?: Array<string>;
  SensitiveKeywordSettings?: Array<SensitiveKeywordSettingModel>;
  SslTlsSettingModel?: SslTlsSettingModel;
  WebStorageSettings?: Array<WebStorageSetting>;
  ExtensionSettings?: Array<ExtensionSettingModel>;
  ResourceFinders?: Array<string>;
  ClonedScanPolicySettingId?: string;
};

export type SaveScanProfileApiModel = {
  AgentGroupId?: string;
  AgentId?: string;
  CreateType?: string;
  IsPrimary?: boolean;
  IsShared?: boolean;
  IsTimeWindowEnabled?: boolean;
  PolicyId?: string;
  ProfileId?: string;
  ProfileName: string;
  ReportPolicyId?: string;
  TargetUri?: string;
  UserId?: string;
  AdditionalWebsites?: Array<AdditionalWebsiteModel>;
  BasicAuthenticationApiModel?: BasicAuthenticationSettingModel;
  ClientCertificateAuthenticationSetting?: ClientCertificateAuthenticationApiModel;
  Cookies?: string;
  CrawlAndAttack?: boolean;
  EnableHeuristicChecksInCustomUrlRewrite?: boolean;
  ExcludedLinks?: Array<ExcludedLinkModel>;
  ExcludedUsageTrackers?: Array<ExcludedUsageTrackerModel>;
  DisallowedHttpMethods?: Array<string>;
  ExcludeLinks?: boolean;
  ExcludeAuthenticationPages?: boolean;
  FindAndFollowNewLinks?: boolean;
  FormAuthenticationSettingModel?: FormAuthenticationSettingModel;
  HeaderAuthentication?: HeaderAuthenticationModel;
  SharkSetting?: SharkModel;
  AuthenticationProfileOption?: string;
  AuthenticationProfileId?: string;
  ImportedLinks?: Array<string>;
  ImportedFiles?: Array<ApiFileModel>;
  IsMaxScanDurationEnabled?: boolean;
  MaxDynamicSignatures?: number;
  MaxScanDuration?: number;
  Scope?: string;
  SubPathMaxDynamicSignatures?: number;
  TimeWindow?: ScanTimeWindowModel;
  UrlRewriteAnalyzableExtensions?: string;
  UrlRewriteBlockSeparators?: string;
  UrlRewriteMode?: string;
  UrlRewriteRules?: Array<UrlRewriteRuleModel>;
  PreRequestScriptSetting?: PreRequestScriptSettingModel;
  DoNotDifferentiateProtocols?: boolean;
  UrlRewriteExcludedLinks?: Array<UrlRewriteExcludedPathModel>;
  OAuth2SettingModel?: OAuth2SettingApiModel;
  EnablePciScanTask?: boolean;
};

export type AdditionalWebsiteModel = {
  Canonical?: boolean;
  TargetUrl?: string;
};

export type BasicAuthenticationSettingModel = {
  Credentials?: Array<BasicAuthenticationCredentialModel>;
  IsEnabled?: boolean;
  NoChallenge?: boolean;
};

export type ClientCertificateAuthenticationApiModel = {
  File: ApiFileModel;
  IsEnabled?: boolean;
  Password?: string;
};

export type ExcludedLinkModel = {
  RegexPattern: string;
};

export type ExcludedUsageTrackerModel = {
  Url: string;
};

export type FormAuthenticationSettingModel = {
  Integrations?: { [key: string]: ScanNotificationIntegrationViewModel };
  CustomScripts?: Array<FormAuthenticationCustomScript>;
  InteractiveLoginRequired?: boolean;
  DefaultPersonaValidation?: boolean;
  DetectBearerToken?: boolean;
  DisableLogoutDetection?: boolean;
  IsEnabled?: boolean;
  LoginFormUrl?: string;
  LoginRequiredUrl?: string;
  LogoutKeywordPatterns?: Array<LogoutKeywordPatternModel>;
  LogoutKeywordPatternsValue?: string;
  LogoutRedirectPattern?: string;
  OverrideTargetUrl?: boolean;
  Personas?: Array<FormAuthenticationPersona>;
  PersonasValidation?: boolean;
};

export type HeaderAuthenticationModel = {
  Headers?: Array<CustomHttpHeaderModel>;
  IsEnabled?: boolean;
};

export type SharkModel = {
  IsSharkEnabled?: boolean;
  SharkPlatformType?: string;
  SharkPassword?: string;
};

export type ApiFileModel = {
  Content: string;
  FileName?: string;
  ImporterType?: string;
};

export type ScanTimeWindowModel = {
  Items?: Array<ScanTimeWindowItemModel>;
};

export type UrlRewriteRuleModel = {
  PlaceholderPattern?: string;
  RegexPattern?: string;
};

export type PreRequestScriptSettingModel = {
  IsEnabled?: boolean;
  Content?: string;
};

export type UrlRewriteExcludedPathModel = {
  ExcludedPath?: string;
  IsRegex?: boolean;
};

export type OAuth2SettingApiModel = {
  FlowType?: string;
  AuthenticationType?: string;
  AccessTokenEndpoint?: OAuth2SettingEndpoint;
  AuthorizationCodeEndpoint?: OAuth2SettingEndpoint;
  AccessTokenItems?: Array<NameValuePair>;
  AuthorizationCodeItems?: Array<NameValuePair>;
  ResponseFields?: ResponseFields;
  ThreeLeggedFields?: ThreeLeggedFields;
  Id?: string;
  Headers?: Array<NameValuePair>;
  FormAuthenticationSetting?: FormAuthenticationSettingApiModel;
  BasicAuthenticationSetting?: BasicAuthenticationSettingApiModel;
};

export type BasicAuthenticationCredentialModel = {
  AuthenticationType?: string;
  Domain?: string;
  Password: string;
  UriPrefix?: string;
  UserName?: string;
  OriginalUriPrefix?: string;
  OriginalUserName?: string;
  IsReplacedCredentials?: boolean;
};

export type ScanNotificationIntegrationViewModel = {
  AsanaInfo?: AsanaIntegrationInfoModel;
  AzureDevopsInfo?: AzureDevOpsIntegrationInfoModel;
  BitbucketInfo?: BitbucketIntegrationInfoModel;
  Bugzilla?: BugzillaIntegrationInfoModel;
  Category?: string;
  ClubhouseInfo?: ClubhouseIntegrationInfoModel;
  PivotalTrackerInfo?: PivotalTrackerIntegrationInfoModel;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  FogBugzInfo?: FogBugzIntegrationInfoModel;
  GitHubInfo?: GitHubIntegrationInfoModel;
  GitLabInfo?: GitLabIntegrationInfoModel;
  Id?: string;
  JiraInfo?: JiraIntegrationInfoModel;
  KafkaInfo?: KafkaIntegrationInfoModel;
  KennaInfo?: KennaIntegrationInfoModel;
  FreshserviceInfo?: FreshserviceIntegrationInfoModel;
  YouTrackInfo?: YouTrackIntegrationInfoModel;
  MicrosoftTeamsInfo?: MicrosoftTeamsIntegrationInfoModel;
  Name: string;
  NotFound?: boolean;
  PagerDutyInfo?: PagerDutyIntegrationInfoModel;
  RedmineInfo?: RedmineIntegrationInfoModel;
  ServiceNowInfo?: ServiceNowIntegrationInfoModel;
  SlackInfo?: SlackIntegrationInfoModel;
  MattermostInfo?: MattermostIntegrationInfoModel;
  TFSInfo?: TFSIntegrationInfoModel;
  TrelloInfo?: TrelloIntegrationInfoModel;
  Type?: string;
  UnfuddleInfo?: UnfuddleIntegrationInfoModel;
  WebhookInfo?: WebhookIntegrationInfoModel;
  ZapierInfo?: ZapierIntegrationInfoModel;
  VaultInfo?: HashicorpVaultIntegrationInfoModel;
  CyberArkVaultInfo?: CyberArkVaultIntegrationInfoModel;
};

export type FormAuthenticationCustomScript = {
  Value: string;
};

export type LogoutKeywordPatternModel = {
  Pattern: string;
  Regex?: boolean;
};

export type FormAuthenticationPersona = {
  IsActive?: boolean;
  Password?: string;
  UserName: string;
  OtpType?: string;
  SecretKey?: string;
  Digit?: string;
  Period?: number;
  Algorithm?: string;
  FormAuthType?: string;
  IntegrationId?: string;
  Version?: string;
  SecretEngine?: string;
  Secret?: string;
  UseStaticUsername?: boolean;
  StaticUsername?: string;
  UsernameKey?: string;
  PasswordKey?: string;
  CyberArkUseStaticUsername?: boolean;
  CyberArkStaticUsername?: string;
  CyberArkUserNameQuery?: string;
  CyberArkPasswordQuery?: string;
  OriginalUserName?: string;
  IsReplacedCredentials?: boolean;
};

export type CustomHttpHeaderModel = {
  Name: string;
  Value?: string;
  OriginalName?: string;
  IsReplacedCredentials?: boolean;
};

export type ScanTimeWindowItemModel = {
  Day?: string;
  From?: string;
  ScanningAllowed?: boolean;
  To?: string;
};

export type OAuth2SettingEndpoint = {
  Url?: string;
  ContentType?: string;
  Method?: string;
};

export type NameValuePair = {
  Name?: string;
  Value?: string;
  IsEncrypted?: boolean;
};

export type ResponseFields = {
  AccessToken?: string;
  RefreshToken?: string;
  Expire?: string;
  TokenType?: string;
  IsTokenTypeFixed?: boolean;
};

export type ThreeLeggedFields = {
  Enabled?: boolean;
  Username?: string;
  Password?: string;
  OtpSettings?: OtpSettings;
  CustomScripts?: Array<string>;
};

export type FormAuthenticationSettingApiModel = {
  CustomScripts?: Array<FormAuthenticationCustomScript>;
  DetectBearerToken?: boolean;
  DetectAuthorizationTokens?: boolean;
  DisableLogoutDetection?: boolean;
  LoginFormUrl?: string;
  LoginRequiredUrl?: string;
  LogoutKeywordPatterns?: string;
  LogoutRedirectPattern?: string;
  OverrideTargetUrlWithAuthenticatedPage?: boolean;
  Password?: string;
  UserName?: string;
  FormAuthType?: string;
  OtpSettings?: OtpSettings;
  HashicorpVaultSetting?: FormAuthenticationHashicorpVaultSetting;
  CyberArkVaultSetting?: FormAuthenticationCyberArkVaultSetting;
};

export type BasicAuthenticationSettingApiModel = {
  AlwaysAuthenticateNoChallenge?: boolean;
  Credentials?: Array<BasicAuthenticationCredentialApiModel>;
};

export type AsanaIntegrationInfoModel = {
  AccessToken: string;
  ProjectId?: string;
  WorkspaceId?: string;
  Assignee?: string;
  FollowerIds?: Array<string>;
  DueDays?: number;
  Type?: string;
  TagIds?: Array<string>;
  WorkspaceList?: Array<AsanaWorkspace>;
  ProjectList?: Array<AsanaProject>;
  AssigneeList?: Array<AsanaUser>;
  FollowerList?: Array<AsanaUser>;
  TagList?: Array<AsanaTag>;
  FollowersSelected?: string;
  TagsSelected?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type AzureDevOpsIntegrationInfoModel = {
  Type?: string;
  Password: string;
  Username?: string;
  AssignedTo?: string;
  Domain?: string;
  ProjectUri?: string;
  Tags?: string;
  WorkItemTypeName?: string;
  WebhookUrl?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
};

export type BitbucketIntegrationInfoModel = {
  Kind: string;
  Password?: string;
  Priority?: string;
  Repository?: string;
  Type?: string;
  UsernameOrEmail?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type BugzillaIntegrationInfoModel = {
  Type?: string;
  Url: string;
  ApiKey?: string;
  Product?: string;
  Component?: string;
  Version?: string;
  Platform?: string;
  OperationSystem?: string;
  Status?: string;
  Priority?: string;
  AssignedTo?: string;
  Severity?: string;
  Milestone?: string;
  DueDays?: number;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type ClubhouseIntegrationInfoModel = {
  ApiToken: string;
  ProjectId?: number;
  ClubhouseStoryType?: string;
  EpicId?: number;
  StateId?: number;
  RequesterId?: string;
  OwnerIds?: string;
  FollowerIds?: string;
  DueDays?: number;
  Labels?: string;
  Type?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type PivotalTrackerIntegrationInfoModel = {
  Type?: string;
  ApiToken: string;
  ProjectId?: number;
  StoryType?: string;
  OwnerIds?: string;
  Labels?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type NotificationIntegrationCustomFieldModel = {
  File?: FileCache;
  Name: string;
  Value?: string;
  InputType?: string;
};

export type FogBugzIntegrationInfoModel = {
  Area?: string;
  AssignedTo?: string;
  Category: string;
  Milestone?: string;
  Project?: string;
  Tags?: string;
  Token?: string;
  Type?: string;
  Url?: string;
  WebhookUrl?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
};

export type GitHubIntegrationInfoModel = {
  AccessToken: string;
  ServerUrl?: string;
  Assignee?: string;
  Labels?: string;
  Repository?: string;
  Type?: string;
  Username?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type GitLabIntegrationInfoModel = {
  AccessToken: string;
  AssigneeId?: number;
  DueDays?: number;
  Labels?: string;
  MilestoneId?: number;
  OnPremiseBaseURL?: string;
  ProjectId?: number;
  Type?: string;
  Weight?: number;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type JiraIntegrationInfoModel = {
  AssignedTo?: string;
  AutoAssignToPerson?: boolean;
  DueDays?: number;
  IsCloud?: boolean;
  IssueType: string;
  Labels?: string;
  Components?: string;
  MappedJiraUsers?: Array<IntegrationUserMappingItemModel>;
  Password?: string;
  Priority?: string;
  SecurityLevel?: string;
  ProjectKey?: string;
  ReopenStatus?: string;
  ReopenStatusJira?: string;
  Reporter?: string;
  Type?: string;
  Url?: string;
  UsernameOrEmail?: string;
  WebhookUrl?: string;
  TemplateType?: string;
  EpicName?: string;
  EpicNameCustomFieldName?: string;
  EpicKey?: string;
  EpicKeyCustomFieldName?: string;
  EpicSelectionType?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
};

export type KafkaIntegrationInfoModel = {
  Topic: string;
  DataSerialization?: string;
  SchemaRegistryUrl?: string;
  Type?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type KennaIntegrationInfoModel = {
  ApiKey: string;
  ApiUrl?: string;
  DueDays?: number;
  SetAssetApplicationIdentifier?: boolean;
  AssetApplicationIdentifierType?: string;
  InstanceUrl?: string;
  Type?: string;
  AssetApplicationIdentifier?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type FreshserviceIntegrationInfoModel = {
  ServerUrl: string;
  ApiKey?: string;
  RequesterId?: number;
  GroupId?: number;
  AgentId?: number;
  PriorityId?: number;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  Requesters?: Array<FreshserviceUser>;
  Groups?: Array<FreshserviceEntity>;
  Agents?: Array<FreshserviceUser>;
  Priorities?: Array<FreshserviceEntity>;
  DueDays?: number;
  Type?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type YouTrackIntegrationInfoModel = {
  ServerUrl: string;
  Token?: string;
  ProjectId?: string;
  Tags?: string;
  Type?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type MicrosoftTeamsIntegrationInfoModel = {
  Type?: string;
  WebhookUrl: string;
  Color?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
};

export type PagerDutyIntegrationInfoModel = {
  ApiAccessKey: string;
  ApiUrl?: string;
  BodyDetails?: string;
  From?: string;
  IncidentBodyType?: string;
  IncidentType?: string;
  ServiceId?: string;
  ServiceType?: string;
  Title?: string;
  Type?: string;
  Urgency?: string;
  Url?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type RedmineIntegrationInfoModel = {
  Url: string;
  Type?: string;
  ApiAccessKey?: string;
  Project?: string;
  PriorityId?: number;
  TrackerId?: number;
  StatusId?: number;
  CategoryId?: number;
  AssignedTo?: number;
  DueDays?: number;
  IsPrivate?: boolean;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type ServiceNowIntegrationInfoModel = {
  AssignedToId?: string;
  CallerId?: string;
  ServiceNowCategoryTypes?: string;
  CategoryTypes: string;
  ReopenStatus?: string;
  ServiceNowReopenCategoryType?: string;
  ServiceNowOnHoldReasonType?: string;
  CloseTheFixedVulnerabilities?: boolean;
  Category?: string;
  DueDays?: number;
  Severity?: number;
  Password?: string;
  ResolvedStatus?: string;
  ResolvedStatusServiceNow?: string;
  Type?: string;
  Url?: string;
  WebhookUrl?: string;
  Username?: string;
  TemplateType?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
};

export type SlackIntegrationInfoModel = {
  Type?: string;
  IncomingWebhookUrl: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type MattermostIntegrationInfoModel = {
  Type?: string;
  IncomingWebhookUrl: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type TFSIntegrationInfoModel = {
  AssignedTo?: string;
  Domain?: string;
  Password: string;
  ProjectUri?: string;
  Tags?: string;
  Type?: string;
  Username?: string;
  WorkItemTypeName?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type TrelloIntegrationInfoModel = {
  ApiKey: string;
  Token?: string;
  ListId?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  BoardId?: string;
  BoardIds?: Array<TrelloBoard>;
  Lists?: Array<TrelloList>;
  Members?: Array<TrelloMember>;
  Labels?: Array<TrelloLabel>;
  MemberIds?: Array<string>;
  LabelIds?: Array<string>;
  LabelIdsSelected?: string;
  MemberIdsSelected?: string;
  DueDays?: number;
  Type?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type UnfuddleIntegrationInfoModel = {
  AssigneeId: number;
  DueDays?: number;
  MilestoneId?: number;
  Password?: string;
  Priority?: number;
  ProjectId?: number;
  Subdomain?: string;
  Type?: string;
  Username?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type WebhookIntegrationInfoModel = {
  HttpMethodType?: string;
  ParameterType?: string;
  Url: string;
  Issue?: string;
  CustomHttpHeaderModels?: Array<CustomHttpHeaderModel>;
  Title?: string;
  Body?: string;
  Username?: string;
  Password?: string;
  Type?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type ZapierIntegrationInfoModel = {
  Type?: string;
  WebhookUrl: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
};

export type HashicorpVaultIntegrationInfoModel = {
  Token: string;
  Type?: string;
  Url?: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type CyberArkVaultIntegrationInfoModel = {
  CertificateFileKey?: string;
  CertificateFilePassword?: string;
  Type?: string;
  Url: string;
  AccountID?: string;
  CustomFields?: Array<NotificationIntegrationCustomFieldModel>;
  GenericErrorMessage?: string;
  Identifier?: string;
  Name?: string;
  ReopenStatus?: string;
  IntegrationWizardResultModel?: IntegrationWizardResultModel;
  ResolvedStatus?: string;
  TestMessageBody?: string;
  TestMessageTitle?: string;
  TitleFormat?: string;
  WebhookUrl?: string;
};

export type OtpSettings = {
  OtpType?: string;
  SecretKey?: string;
  Digit?: string;
  Period?: number;
  Algorithm?: string;
};

export type FormAuthenticationHashicorpVaultSetting = {
  IntegrationId?: string;
  Version?: string;
  SecretEngine?: string;
  Secret?: string;
  UseStaticUsername?: boolean;
  StaticUsername?: string;
  UsernameKey?: string;
  PasswordKey?: string;
};

export type FormAuthenticationCyberArkVaultSetting = {
  IntegrationId?: string;
  CyberArkUseStaticUsername?: boolean;
  CyberArkStaticUsername?: string;
  CyberArkUserNameQuery?: string;
  CyberArkPasswordQuery?: string;
};

export type BasicAuthenticationCredentialApiModel = {
  AuthenticationType?: string;
  Domain?: string;
  Password?: string;
  UriPrefix?: string;
  UserName?: string;
};

export type AsanaWorkspace = {
  gid?: string;
  name?: string;
};

export type AsanaProject = {
  gid?: string;
  name?: string;
  Url?: string;
};

export type AsanaUser = {
  email?: string;
  gid?: string;
  name?: string;
  DisplayName?: string;
};

export type AsanaTag = {
  Gid?: string;
  Name?: string;
};

export type IntegrationWizardResultModel = {
  Status?: boolean;
  ErrorMessage?: string;
};

export type FileCache = {
  Key?: string;
  FileName?: string;
  Id?: number;
  Accept?: string;
  ImporterType?: string;
};

export type IntegrationUserMappingItemModel = {
  Email?: string;
  Id?: string;
  IntegrationSystem: string;
  IntegrationUserName?: string;
  IsEdit?: boolean;
  Name?: string;
  NameEmail?: string;
  Result?: string;
  UserId?: string;
};

export type FreshserviceUser = {
  email?: string;
  id?: number;
  name?: string;
};

export type FreshserviceEntity = {
  id?: number;
  name?: string;
};

export type TrelloBoard = {
  closed?: boolean;
  id?: string;
  IsActive?: boolean;
  name?: string;
  shortUrl?: string;
};

export type TrelloList = {
  closed?: boolean;
  id?: string;
  IsActive?: boolean;
  name?: string;
};

export type TrelloMember = {
  confirmed?: boolean;
  email?: string;
  fullname?: string;
  id?: string;
  shortUrl?: string;
  username?: string;
};

export type TrelloLabel = {
  color?: string;
  id?: string;
  name?: string;
};

export type ScanProfilesListApiResult = {
  FirstItemOnPage?: number;
  HasNextPage?: boolean;
  HasPreviousPage?: boolean;
  IsFirstPage?: boolean;
  IsLastPage?: boolean;
  LastItemOnPage?: number;
  List?: Array<SaveScanProfileApiModel>;
  PageCount?: number;
  PageNumber?: number;
  PageSize?: number;
  TotalItemCount?: number;
};

export type ScanCustomReportApiModel = {
  ExcludeIgnoreds?: boolean;
  Id: string;
  OnlyConfirmedVulnerabilities?: boolean;
  OnlyUnconfirmedVulnerabilities?: boolean;
  ReportName?: string;
  ReportFormat?: string;
};

export type ScanTaskModel = {
  AdditionalWebsites?: Array<AdditionalWebsiteModel>;
  AgentId?: string;
  AgentName?: string;
  Cookies?: string;
  CrawlAndAttack?: boolean;
  EnableHeuristicChecksInCustomUrlRewrite?: boolean;
  ExcludedLinks?: string;
  ExcludeLinks?: boolean;
  DisallowedHttpMethods?: string;
  FindAndFollowNewLinks?: boolean;
  ImportedLinks?: string;
  DesktopScanId?: string;
  InitiatedTime?: string;
  InitiatedDate?: string;
  InitiatedAt?: string;
  MaxDynamicSignatures?: number;
  MaxScanDuration?: number;
  Duration?: string;
  PolicyDescription?: string;
  PolicyId?: string;
  PolicyName?: string;
  AuthenticationProfileId?: string;
  AuthenticationProfileOption?: string;
  ReportPolicyDescription?: string;
  ReportPolicyId?: string;
  ReportPolicyName?: string;
  Scope?: string;
  SubPathMaxDynamicSignatures?: number;
  TargetPath?: string;
  TargetUrl?: string;
  TargetUrlRoot?: string;
  TimeWindow?: ScanTimeWindowModel;
  TotalVulnerabilityCount?: number;
  UrlRewriteAnalyzableExtensions?: string;
  UrlRewriteBlockSeparators?: string;
  UrlRewriteMode?: string;
  UrlRewriteRules?: Array<UrlRewriteRuleModel>;
  UrlRewriteExcludedLinks?: Array<UrlRewriteExcludedPathModel>;
  UserId?: string;
  VcsCommitInfo?: VcsCommitInfo;
  WebsiteName?: string;
  WebsiteUrl?: string;
  WebsiteDescription?: string;
  EnablePciScanTask?: boolean;
  PciScanTask?: PciScanTaskViewModel;
  UserName?: string;
  QueuedScanTaskExist?: boolean;
  ScanTaskProfileId?: string;
  ScanTaskProfile?: ReducedScanTaskProfile;
  CompletedSteps?: number;
  EstimatedLaunchTime?: number;
  EstimatedSteps?: number;
  FailureReason?: string;
  FailureReasonDescription?: string;
  FailureReasonString?: string;
  GlobalThreatLevel?: string;
  GlobalVulnerabilityCriticalCount?: number;
  GlobalVulnerabilityHighCount?: number;
  GlobalVulnerabilityInfoCount?: number;
  GlobalVulnerabilityBestPracticeCount?: number;
  GlobalVulnerabilityLowCount?: number;
  GlobalVulnerabilityMediumCount?: number;
  Id?: string;
  IsCompleted?: boolean;
  Percentage?: number;
  Phase?: string;
  ScanTaskGroupId?: string;
  ScanType?: string;
  ScheduledScanId?: string;
  State?: string;
  StateChanged?: string;
  ThreatLevel?: string;
  VulnerabilityCriticalCount?: number;
  VulnerabilityHighCount?: number;
  VulnerabilityInfoCount?: number;
  VulnerabilityBestPracticeCount?: number;
  VulnerabilityLowCount?: number;
  VulnerabilityMediumCount?: number;
  WebsiteId?: string;
  Initiated?: string;
};

export type VcsCommitInfo = {
  CiBuildConfigurationName?: string;
  CiBuildHasChange?: boolean;
  CiBuildId?: string;
  CiBuildServerName?: string;
  CiBuildServerVersion?: string;
  CiBuildUrl?: string;
  CiNcPluginVersion?: string;
  CiTimestamp?: string;
  ComitterId?: string;
  Committer?: string;
  CommitterName?: string;
  CommitterOverride?: string;
  IntegrationSystem?: string;
  IsCommiterExistAndAuthorizedInNc?: boolean;
  VcsName?: string;
  VcsVersion?: string;
};

export type PciScanTaskViewModel = {
  Name?: string;
  Progress?: number;
  ScanState?: string;
  ComplianceStatus?: string;
  EndDate?: string;
};

export type ReducedScanTaskProfile = {
  Id?: string;
  IsMine?: boolean;
  IsPrimary?: boolean;
  IsShared?: boolean;
  Name?: string;
  TargetUrl?: string;
  ScanPolicyName?: string;
};

export type IncrementalApiModel = {
  IsMaxScanDurationEnabled?: boolean;
  MaxScanDuration?: number;
  AgentName?: string;
  BaseScanId: string;
};

export type ScanTaskListApiResult = {
  FirstItemOnPage?: number;
  HasNextPage?: boolean;
  HasPreviousPage?: boolean;
  IsFirstPage?: boolean;
  IsLastPage?: boolean;
  LastItemOnPage?: number;
  List?: Array<ScanTaskModel>;
  PageCount?: number;
  PageNumber?: number;
  PageSize?: number;
  TotalItemCount?: number;
};

export type ScheduledScanListApiResult = {
  FirstItemOnPage?: number;
  HasNextPage?: boolean;
  HasPreviousPage?: boolean;
  IsFirstPage?: boolean;
  IsLastPage?: boolean;
  LastItemOnPage?: number;
  List?: Array<ScheduledScanModel>;
  PageCount?: number;
  PageNumber?: number;
  PageSize?: number;
  TotalItemCount?: number;
};

export type ScheduledScanModel = {
  LastExecutedScanTaskId?: string;
  LastExecutionError?: number;
  LastExecutionStatus?: string;
  TimeWindow?: ScanTimeWindowModel;
  Id?: string;
  OccurencesCount?: number;
  Disabled?: boolean;
  EnableScheduling?: boolean;
  Name?: string;
  NextExecutionTime?: string;
  ScanGroupId?: string;
  ScanType?: string;
  ScheduleRunType?: string;
  CustomRecurrence?: ScheduledScanRecurrenceViewModel;
  CustomScriptTemplateType?: string;
  IsTargetUrlRequired?: boolean;
  IsGenerateOptimizedCss?: boolean;
  LaunchSettingId?: string;
  AdditionalWebsites?: AdditionalWebsitesSettingModel;
  AgentGroupId?: string;
  AgentId?: string;
  BasicAuthenticationSetting?: BasicAuthenticationSettingModel;
  CanEdit?: boolean;
  ClientCertificateAuthentication?: ClientCertificateAuthenticationViewModel;
  Cookies?: string;
  Comments?: string;
  CrawlAndAttack?: boolean;
  CreateType?: string;
  AuthenticationProfileOption?: string;
  AuthenticationProfileName?: string;
  FindAndFollowNewLinks?: boolean;
  FormAuthenticationSetting?: FormAuthenticationSettingModel;
  HeaderAuthentication?: HeaderAuthenticationModel;
  Shark?: SharkModel;
  ImportedLinks?: ImportedLinksSetting;
  IsMaxScanDurationEnabled?: boolean;
  IsPrimary?: boolean;
  IsShared?: boolean;
  MaxScanDuration?: number;
  PolicyId?: string;
  PolicyName?: string;
  ProfileId?: string;
  ProfileName?: string;
  ReportPolicyId?: string;
  ReportPolicyName?: string;
  SaveScanProfile?: boolean;
  ScopeSetting?: ScopeSetting;
  SelectedAgents?: Array<AgentSelectionModel>;
  SelectedScanProfileId?: string;
  SelectedScanProfileName?: string;
  TargetUrl?: string;
  Description?: string;
  UrlRewriteSetting?: UrlRewriteSetting;
  PreRequestScriptSetting?: PreRequestScriptSettingModel;
  UserId?: string;
  WebsiteGroupId?: string;
  EnablePciScanTask?: boolean;
  OAuth2Setting?: OAuth2SettingModel;
};

export type ScheduledScanRecurrenceViewModel = {
  RepeatType?: string;
  Interval?: number;
  StartDate?: string;
  EndingType?: string;
  DaysOfWeek?: Array<string>;
  MonthsOfYear?: Array<string>;
  Ordinal?: string;
  EndOn?: string;
  EndOnOccurences?: number;
  DayOfMonth?: number;
  EndOnDate?: string;
  DayOfWeek?: string;
};

export type AdditionalWebsitesSettingModel = {
  Websites?: Array<AdditionalWebsiteModel>;
};

export type ClientCertificateAuthenticationViewModel = {
  IsReplacedCredentials?: boolean;
  File?: FileCache;
  IsEnabled?: boolean;
  Password?: string;
};

export type ImportedLinksSetting = {
  ImportedFiles?: Array<FileCache>;
  ImportedLinks?: string;
};

export type ScopeSetting = {
  ExcludedLinks?: Array<ExcludedLinkModel>;
  ExcludeLinks?: boolean;
  ExcludedUsageTrackers?: Array<ExcludedUsageTrackerModel>;
  ExcludeAuthenticationPages?: boolean;
  DisallowedHttpMethods?: Array<string>;
  Scope?: string;
  DoNotDifferentiateProtocols?: boolean;
};

export type AgentSelectionModel = {
  AgentId?: string;
  WebsiteId?: string;
};

export type UrlRewriteSetting = {
  EnableHeuristicChecksInCustomUrlRewrite?: boolean;
  MaxDynamicSignatures: number;
  SubPathMaxDynamicSignatures?: number;
  UrlRewriteAnalyzableExtensions?: string;
  UrlRewriteBlockSeparators?: string;
  UrlRewriteMode?: string;
  UrlRewriteRules?: Array<UrlRewriteRuleModel>;
  UrlRewriteExcludedLinks?: Array<UrlRewriteExcludedPathModel>;
};

export type OAuth2SettingModel = {
  Enabled?: boolean;
  SelectedFlowType?: string;
  SelectedAuthenticationType?: string;
  FlowTypes?: Array<SelectOptionModel>;
  Authentications?: Array<SelectOptionModel>;
  AccessTokenEndpoint?: OAuth2SettingEndPointModel;
  AuthorizationCodeEndpoint?: OAuth2SettingEndPointModel;
  AccessTokenTable?: AccessTokenTableModel;
  AuthorizationCodeTable?: AuthorizationCodeTableModel;
  ResponseFieldForm?: ResponseFields;
  ThreeLegged?: ThreeLeggedFields;
};

export type SelectOptionModel = {
  Label?: string;
  Value?: {};
};

export type OAuth2SettingEndPointModel = {
  Url?: string;
  ContentType?: string;
  ContentTypeTemplates?: Array<ContentTypeTemplate>;
  Method?: string;
  MethodTemplates?: Array<SelectOptionModel>;
};

export type AccessTokenTableModel = {
  Fields?: Array<string>;
  Items?: { [key: string]: Array<NameValuePair> };
};

export type AuthorizationCodeTableModel = {
  Fields?: Array<string>;
  Items?: Array<NameValuePair>;
};

export type ContentTypeTemplate = {
  Name?: string;
};

export type NewScanTaskApiModel = {
  TargetUri: string;
  AdditionalWebsites?: Array<AdditionalWebsiteModel>;
  BasicAuthenticationApiModel?: BasicAuthenticationSettingModel;
  ClientCertificateAuthenticationSetting?: ClientCertificateAuthenticationApiModel;
  Cookies?: string;
  CrawlAndAttack?: boolean;
  EnableHeuristicChecksInCustomUrlRewrite?: boolean;
  ExcludedLinks?: Array<ExcludedLinkModel>;
  ExcludedUsageTrackers?: Array<ExcludedUsageTrackerModel>;
  DisallowedHttpMethods?: Array<string>;
  ExcludeLinks?: boolean;
  ExcludeAuthenticationPages?: boolean;
  FindAndFollowNewLinks?: boolean;
  FormAuthenticationSettingModel?: FormAuthenticationSettingModel;
  HeaderAuthentication?: HeaderAuthenticationModel;
  SharkSetting?: SharkModel;
  AuthenticationProfileOption?: string;
  AuthenticationProfileId?: string;
  ImportedLinks?: Array<string>;
  ImportedFiles?: Array<ApiFileModel>;
  IsMaxScanDurationEnabled?: boolean;
  MaxDynamicSignatures?: number;
  MaxScanDuration?: number;
  PolicyId?: string;
  ReportPolicyId?: string;
  Scope?: string;
  SubPathMaxDynamicSignatures?: number;
  TimeWindow?: ScanTimeWindowModel;
  UrlRewriteAnalyzableExtensions?: string;
  UrlRewriteBlockSeparators?: string;
  UrlRewriteMode?: string;
  UrlRewriteRules?: Array<UrlRewriteRuleModel>;
  PreRequestScriptSetting?: PreRequestScriptSettingModel;
  DoNotDifferentiateProtocols?: boolean;
  UrlRewriteExcludedLinks?: Array<UrlRewriteExcludedPathModel>;
  OAuth2SettingModel?: OAuth2SettingApiModel;
  EnablePciScanTask?: boolean;
};

export type NewGroupScanApiModel = {
  PolicyId?: string;
  ReportPolicyId?: string;
  AuthenticationProfileOption?: string;
  AuthenticationProfileId?: string;
  TimeWindow?: ScanTimeWindowModel;
  WebsiteGroupName: string;
};

export type NewScanTaskWithProfileApiModel = {
  ProfileName: string;
  TargetUri?: string;
};

export type ScanReportApiModel = {
  ContentFormat?: string;
  ExcludeResponseData?: boolean;
  Format: string;
  Id?: string;
  Type?: string;
  OnlyConfirmedIssues?: boolean;
  OnlyUnconfirmedIssues?: boolean;
  ExcludeAddressedIssues?: boolean;
};

export type VulnerabilityModel = {
  IssueUrl?: string;
  Title?: string;
  Type?: string;
  Url?: string;
};

export type BaseScanApiModel = {
  AgentName?: string;
  BaseScanId: string;
};

export type NewScheduledScanApiModel = {
  Name: string;
  NextExecutionTime?: string;
  ScheduleRunType?: string;
  CustomRecurrence?: ScheduledScanRecurrenceApiModel;
  TargetUri?: string;
  AdditionalWebsites?: Array<AdditionalWebsiteModel>;
  BasicAuthenticationApiModel?: BasicAuthenticationSettingModel;
  ClientCertificateAuthenticationSetting?: ClientCertificateAuthenticationApiModel;
  Cookies?: string;
  CrawlAndAttack?: boolean;
  EnableHeuristicChecksInCustomUrlRewrite?: boolean;
  ExcludedLinks?: Array<ExcludedLinkModel>;
  ExcludedUsageTrackers?: Array<ExcludedUsageTrackerModel>;
  DisallowedHttpMethods?: Array<string>;
  ExcludeLinks?: boolean;
  ExcludeAuthenticationPages?: boolean;
  FindAndFollowNewLinks?: boolean;
  FormAuthenticationSettingModel?: FormAuthenticationSettingModel;
  HeaderAuthentication?: HeaderAuthenticationModel;
  SharkSetting?: SharkModel;
  AuthenticationProfileOption?: string;
  AuthenticationProfileId?: string;
  ImportedLinks?: Array<string>;
  ImportedFiles?: Array<ApiFileModel>;
  IsMaxScanDurationEnabled?: boolean;
  MaxDynamicSignatures?: number;
  MaxScanDuration?: number;
  PolicyId?: string;
  ReportPolicyId?: string;
  Scope?: string;
  SubPathMaxDynamicSignatures?: number;
  TimeWindow?: ScanTimeWindowModel;
  UrlRewriteAnalyzableExtensions?: string;
  UrlRewriteBlockSeparators?: string;
  UrlRewriteMode?: string;
  UrlRewriteRules?: Array<UrlRewriteRuleModel>;
  PreRequestScriptSetting?: PreRequestScriptSettingModel;
  DoNotDifferentiateProtocols?: boolean;
  UrlRewriteExcludedLinks?: Array<UrlRewriteExcludedPathModel>;
  OAuth2SettingModel?: OAuth2SettingApiModel;
  EnablePciScanTask?: boolean;
};

export type ScheduledScanRecurrenceApiModel = {
  RepeatType?: string;
  Interval?: number;
  EndingType?: string;
  DaysOfWeek?: Array<string>;
  MonthsOfYear?: Array<string>;
  Ordinal?: string;
  EndOn?: string;
  EndOnOccurences?: number;
  DayOfMonth?: number;
  DayOfWeek?: string;
};

export type UpdateScheduledScanModel = {
  Id?: string;
  OccurencesCount?: number;
  Disabled?: boolean;
  EnableScheduling?: boolean;
  Name?: string;
  NextExecutionTime?: string;
  ScanGroupId?: string;
  ScanType?: string;
  ScheduleRunType?: string;
  CustomRecurrence?: ScheduledScanRecurrenceViewModel;
  CustomScriptTemplateType?: string;
  IsTargetUrlRequired?: boolean;
  IsGenerateOptimizedCss?: boolean;
  LaunchSettingId?: string;
  AdditionalWebsites?: AdditionalWebsitesSettingModel;
  AgentGroupId?: string;
  AgentId?: string;
  BasicAuthenticationSetting?: BasicAuthenticationSettingModel;
  CanEdit?: boolean;
  ClientCertificateAuthentication?: ClientCertificateAuthenticationViewModel;
  Cookies?: string;
  Comments?: string;
  CrawlAndAttack?: boolean;
  CreateType?: string;
  AuthenticationProfileOption?: string;
  AuthenticationProfileName?: string;
  FindAndFollowNewLinks?: boolean;
  FormAuthenticationSetting?: FormAuthenticationSettingModel;
  HeaderAuthentication?: HeaderAuthenticationModel;
  Shark?: SharkModel;
  ImportedLinks?: ImportedLinksSetting;
  IsMaxScanDurationEnabled?: boolean;
  IsPrimary?: boolean;
  IsShared?: boolean;
  MaxScanDuration?: number;
  PolicyId?: string;
  PolicyName?: string;
  ProfileId?: string;
  ProfileName?: string;
  ReportPolicyId?: string;
  ReportPolicyName?: string;
  SaveScanProfile?: boolean;
  ScopeSetting?: ScopeSetting;
  SelectedAgents?: Array<AgentSelectionModel>;
  SelectedScanProfileId?: string;
  SelectedScanProfileName?: string;
  TargetUrl?: string;
  Description?: string;
  TimeWindow?: ScanTimeWindowViewModel;
  UrlRewriteSetting?: UrlRewriteSetting;
  PreRequestScriptSetting?: PreRequestScriptSettingModel;
  UserId?: string;
  WebsiteGroupId?: string;
  EnablePciScanTask?: boolean;
  OAuth2Setting?: OAuth2SettingModel;
};

export type ScanTimeWindowViewModel = {
  IsEnabled?: boolean;
  IsEnabledForWebsite?: boolean;
  IsEnabledForWebsiteGroup?: boolean;
  Items?: Array<ScanTimeWindowItemViewModel>;
  TimeZone?: string;
  ScanCreateType?: string;
};

export type ScanTimeWindowItemViewModel = {
  Day?: string;
  From?: number;
  ScanningAllowed?: boolean;
  To?: number;
};

export type NewScheduledIncrementalScanApiModel = {
  IsMaxScanDurationEnabled?: boolean;
  MaxScanDuration?: number;
  Name: string;
  NextExecutionTime?: string;
  ScheduleRunType?: string;
  AgentName?: string;
  BaseScanId?: string;
};

export type NewScheduledWithProfileApiModel = {
  ProfileName: string;
  TargetUri?: string;
  Name?: string;
  NextExecutionTime?: string;
  ScheduleRunType?: string;
  CustomRecurrence?: ScheduledScanRecurrenceApiModel;
};

export type ApiScanStatusModel = {
  CompletedSteps?: number;
  EstimatedLaunchTime?: number;
  EstimatedSteps?: number;
  State?: string;
};

export type UpdateScheduledScanApiModel = {
  Disabled?: boolean;
  Id: string;
  Name?: string;
  NextExecutionTime?: string;
  ScheduleRunType?: string;
  CustomRecurrence?: ScheduledScanRecurrenceApiModel;
  TargetUri?: string;
  AdditionalWebsites?: Array<AdditionalWebsiteModel>;
  BasicAuthenticationApiModel?: BasicAuthenticationSettingModel;
  ClientCertificateAuthenticationSetting?: ClientCertificateAuthenticationApiModel;
  Cookies?: string;
  CrawlAndAttack?: boolean;
  EnableHeuristicChecksInCustomUrlRewrite?: boolean;
  ExcludedLinks?: Array<ExcludedLinkModel>;
  ExcludedUsageTrackers?: Array<ExcludedUsageTrackerModel>;
  DisallowedHttpMethods?: Array<string>;
  ExcludeLinks?: boolean;
  ExcludeAuthenticationPages?: boolean;
  FindAndFollowNewLinks?: boolean;
  FormAuthenticationSettingModel?: FormAuthenticationSettingModel;
  HeaderAuthentication?: HeaderAuthenticationModel;
  SharkSetting?: SharkModel;
  AuthenticationProfileOption?: string;
  AuthenticationProfileId?: string;
  ImportedLinks?: Array<string>;
  ImportedFiles?: Array<ApiFileModel>;
  IsMaxScanDurationEnabled?: boolean;
  MaxDynamicSignatures?: number;
  MaxScanDuration?: number;
  PolicyId?: string;
  ReportPolicyId?: string;
  Scope?: string;
  SubPathMaxDynamicSignatures?: number;
  TimeWindow?: ScanTimeWindowModel;
  UrlRewriteAnalyzableExtensions?: string;
  UrlRewriteBlockSeparators?: string;
  UrlRewriteMode?: string;
  UrlRewriteRules?: Array<UrlRewriteRuleModel>;
  PreRequestScriptSetting?: PreRequestScriptSettingModel;
  DoNotDifferentiateProtocols?: boolean;
  UrlRewriteExcludedLinks?: Array<UrlRewriteExcludedPathModel>;
  OAuth2SettingModel?: OAuth2SettingApiModel;
  EnablePciScanTask?: boolean;
};

export type UpdateScheduledIncrementalScanApiModel = {
  Disabled?: boolean;
  Id: string;
  IsMaxScanDurationEnabled?: boolean;
  MaxScanDuration?: number;
  Name?: string;
  NextExecutionTime?: string;
  ScheduleRunType?: string;
  AgentName?: string;
  BaseScanId?: string;
};

export type FormAuthenticationVerificationApiModel = {
  LoginFormUrl: string;
  Password?: string;
  ScanTargetUrl?: string;
  Username?: string;
  OtpSettings?: OtpSettings;
};

export type AuthVerificationApiResult = {
  Keywords?: Array<string>;
  LoginImageBase64?: string;
  LoginRequiredUrl?: string;
  LogoutImageBase64?: string;
  LogoutSignatureType?: string;
  RedirectLocation?: string;
};

export type TestScanProfileCredentialsRequestModel = {
  ProfileId: string;
  Url?: string;
};

export type NewUserApiModel = {
  OnlySsoLogin?: boolean;
  AutoGeneratePassword?: boolean;
  Password?: string;
  SendNotification?: boolean;
  PhoneNumber?: string;
  AccountPermissions?: string;
  TimezoneId: string;
  WebsiteGroups?: string;
  WebsiteGroupNames?: Array<string>;
  ScanPermissions?: string;
  DateTimeFormat?: string;
  Email?: string;
  AlternateLoginEmail?: string;
  Name?: string;
  ConfirmPassword?: string;
  IsApiAccessEnabled?: boolean;
  AllowedWebsiteLimit?: number;
};

export type UserApiModel = {
  AccountId?: string;
  CanManageApplication?: boolean;
  CanManageIssues?: boolean;
  CanManageIssuesAsRestricted?: boolean;
  CanManageTeam?: boolean;
  CanManageWebsites?: boolean;
  CanStartScan?: boolean;
  CanViewScanReports?: boolean;
  CreatedAt?: string;
  DateTimeFormat?: string;
  Email?: string;
  Id?: string;
  IsTwoFactorAuthenticationEnabled?: boolean;
  Name?: string;
  PhoneNumber?: string;
  Role?: string;
  SelectedGroups?: Array<string>;
  TimezoneId?: string;
  UpdatedAt?: string;
  UserState?: string;
  IsApiAccessEnabled?: boolean;
  AllowedWebsiteLimit?: number;
  LastLoginDate?: string;
  AlternateLoginEmail?: string;
};

export type UpdateUserApiModel = {
  Password?: string;
  UserId: string;
  UserState?: string;
  PhoneNumber?: string;
  AccountPermissions?: string;
  TimezoneId?: string;
  WebsiteGroups?: string;
  WebsiteGroupNames?: Array<string>;
  ScanPermissions?: string;
  DateTimeFormat?: string;
  Email?: string;
  AlternateLoginEmail?: string;
  Name?: string;
  ConfirmPassword?: string;
  IsApiAccessEnabled?: boolean;
  AllowedWebsiteLimit?: number;
};

export type TimezoneApiModel = {
  Id?: string;
  Name?: string;
};

export type UserListApiResult = {
  FirstItemOnPage?: number;
  HasNextPage?: boolean;
  HasPreviousPage?: boolean;
  IsFirstPage?: boolean;
  IsLastPage?: boolean;
  LastItemOnPage?: number;
  List?: Array<UserApiModel>;
  PageCount?: number;
  PageNumber?: number;
  PageSize?: number;
  TotalItemCount?: number;
};

export type UserApiTokenModel = {
  Id?: string;
  Token?: string;
};

export type TechnologyListApiResult = {
  FirstItemOnPage?: number;
  HasNextPage?: boolean;
  HasPreviousPage?: boolean;
  IsFirstPage?: boolean;
  IsLastPage?: boolean;
  LastItemOnPage?: number;
  List?: Array<TechnologyApiModel>;
  PageCount?: number;
  PageNumber?: number;
  PageSize?: number;
  TotalItemCount?: number;
};

export type TechnologyApiModel = {
  Category?: string;
  DisplayName?: string;
  EndOfLife?: string;
  Id?: string;
  IdentifiedVersion?: string;
  IsNotificationDisabled?: boolean;
  IsOutofDate?: boolean;
  IssueCriticalCount?: number;
  IssueHighCount?: number;
  IssueInfoCount?: number;
  IssueLowCount?: number;
  IssueMediumCount?: number;
  LastSeenDate?: string;
  LatestVersion?: string;
  Name?: string;
  ScanTaskId?: string;
  WebsiteId?: string;
  WebsiteName?: string;
};

export type VulnerabilityTemplate = {
  Description?: string;
  Actions?: string;
  ExternalReferences?: string;
  Impact?: string;
  ProofOfConcept?: string;
  Remedy?: string;
  RemedyReferences?: string;
  Skills?: string;
  Summary?: string;
  Type?: string;
  TypeId?: string;
  TypeSignature?: string;
  Severity?: string;
  Classification?: VulnerabilityClassification;
  CvssVectorString?: string;
  Cvss31VectorString?: string;
  CvssVector?: {
    Base?: CvssMetricModel;
    Temporal?: CvssMetricModel;
    Environmental?: CvssMetricModel;
  };
  Cvss31Vector?: {
    Base?: CvssMetricModel;
    Temporal?: CvssMetricModel;
    Environmental?: CvssMetricModel;
  };
  Order?: string;
};

export type CustomTemplateModel = {
  source_template_id?: string;
  title?: string;
  description?: string;
  remediation?: string;
  severity?: number;
  template?: CustomTemplateContentModel;
};

export type CustomTemplateContentModel = {
  CVSS?: { [key: string]: {} };
  CATEGORY?: string;
  CVE_LIST?: { [key: string]: {} };
  PCI_FLAG?: string;
  DISCOVERY?: { [key: string]: {} };
  PATCHABLE?: string;
  VULN_TYPE?: string;
};

export type DeleteWebsiteGroupApiModel = {
  Name: string;
};

export type WebsiteGroupApiModel = {
  TotalWebsites?: number;
  CreatedAt?: string;
  UpdatedAt?: string;
  Id: string;
  Name?: string;
  Description?: string;
};

export type WebsiteGroupListApiResult = {
  FirstItemOnPage?: number;
  HasNextPage?: boolean;
  HasPreviousPage?: boolean;
  IsFirstPage?: boolean;
  IsLastPage?: boolean;
  LastItemOnPage?: number;
  List?: Array<WebsiteGroupApiModel>;
  PageCount?: number;
  PageNumber?: number;
  PageSize?: number;
  TotalItemCount?: number;
};

export type NewWebsiteGroupApiModel = {
  Name: string;
  Description?: string;
};

export type UpdateWebsiteGroupApiModel = {
  Id: string;
  Name?: string;
  Description?: string;
};

export type WebsiteListApiResult = {
  FirstItemOnPage?: number;
  HasNextPage?: boolean;
  HasPreviousPage?: boolean;
  IsFirstPage?: boolean;
  IsLastPage?: boolean;
  LastItemOnPage?: number;
  List?: Array<WebsiteApiModel>;
  PageCount?: number;
  PageNumber?: number;
  PageSize?: number;
  TotalItemCount?: number;
};

export type WebsiteApiModel = {
  Id?: string;
  CreatedAt?: string;
  UpdatedAt?: string;
  RootUrl?: string;
  Name?: string;
  Description?: string;
  TechnicalContactEmail?: string;
  Groups?: Array<IdNamePair>;
  IsVerified?: boolean;
  LicenseType?: string;
  AgentMode?: string;
};

export type IdNamePair = {
  Id?: string;
  Name?: string;
};

export type NewWebsiteApiModel = {
  AgentMode?: string;
  RootUrl: string;
  Groups?: Array<string>;
  LicenseType?: string;
  Name?: string;
  Description?: string;
  TechnicalContactEmail?: string;
};

export type VerifyApiModel = {
  VerificationMethod?: string;
  VerificationSecret?: string;
  WebsiteUrl: string;
};

export type StartVerificationApiModel = {
  VerificationMethod: string;
  WebsiteUrl?: string;
};

export type StartVerificationResult = {
  Data?: {};
  Message?: string;
  VerifyOwnershipResult?: string;
};

export type SendVerificationEmailModel = {
  IsMailSent?: boolean;
  VerificationMessage?: string;
};

export type UpdateWebsiteApiModel = {
  DefaultProtocol?: string;
  AgentMode?: string;
  RootUrl: string;
  Groups?: Array<string>;
  LicenseType?: string;
  Name?: string;
  Description?: string;
  TechnicalContactEmail?: string;
};

export type DeleteWebsiteApiModel = {
  RootUrl: string;
};

export type PostApi10AgentgroupsDeleteBodyParameters = AgentGroupApiDeleteModel;

export type GetApi10AgentgroupsListQueryParameters = {
  page?: number;
  pageSize?: number;
};

export type PostApi10AgentgroupsNewBodyParameters = AgentGroupApiNewModel;

export type PostApi10AgentgroupsUpdateBodyParameters = AgentGroupApiUpdateModel;

export type PostApi10AgentsDeleteBodyParameters = DeleteAgentModel;

export type GetApi10AgentsListQueryParameters = {
  page?: number;
  pageSize?: number;
};

export type PostApi10AgentsSetstatusBodyParameters = AgentStatusModel;

export type GetApi10AuditlogsExportQueryParameters = {
  page?: number;
  pageSize?: number;
  csvSeparator?: string;
  startDate?: string;
  endDate?: string;
};

export type PostApi10AuthenticationprofilesDeleteBodyParameters = string;

export type PostApi10AuthenticationprofilesNewBodyParameters =
  AuthenticationProfileViewModel;

export type PostApi10AuthenticationprofilesUpdateBodyParameters =
  AuthenticationProfileViewModel;

export type PostApi10DiscoveryExcludeBodyParameters = ExcludeFilter;

export type GetApi10DiscoveryExportQueryParameters = {
  csvSeparator?: string;
};

export type PostApi10DiscoveryIgnoreBodyParameters = Array<string>;

export type GetApi10DiscoveryIgnorebyfilterQueryParameters = {
  authority?: string;
  ipAddress?: string;
  secondLevelDomain?: string;
  topLevelDomain?: string;
  organizationName?: string;
  distance?: number;
  registeredDomain?: boolean;
};

export type GetApi10DiscoveryListQueryParameters = {
  page?: number;
  pageSize?: number;
};

export type GetApi10DiscoveryListbyfilterQueryParameters = {
  authority?: string;
  ipAddress?: string;
  secondLevelDomain?: string;
  topLevelDomain?: string;
  organizationName?: string;
  distance?: number;
  registeredDomain?: boolean;
  status?: string;
  page?: number;
  pageSize?: number;
};

export type PostApi10DiscoveryUpdateSettingsBodyParameters =
  DiscoverySettingsApiModel;

export type GetApi10IssuesAddressedissuesQueryParameters = {
  severity?: string;
  webSiteName?: string;
  websiteGroupName?: string;
  page?: number;
  pageSize?: number;
};

export type GetApi10IssuesAllissuesQueryParameters = {
  severity?: string;
  webSiteName?: string;
  websiteGroupName?: string;
  page?: number;
  pageSize?: number;
  sortType?: string;
  lastSeenDate?: string;
  rawDetails?: boolean;
};

export type GetApi10IssuesReportQueryParameters = {
  csvSeparator?: string;
  severity?: string;
  websiteGroupName?: string;
  webSiteName?: string;
};

export type GetApi10IssuesTodoQueryParameters = {
  severity?: string;
  webSiteName?: string;
  websiteGroupName?: string;
  page?: number;
  pageSize?: number;
};

export type PostApi10IssuesUpdateBodyParameters = IssueApiUpdateModel;

export type GetApi10IssuesWaitingforretestQueryParameters = {
  severity?: string;
  webSiteName?: string;
  websiteGroupName?: string;
  page?: number;
  pageSize?: number;
};

export type PostApi10NotificationsDeleteBodyParameters =
  DeleteScanNotificationApiModel;

export type GetApi10NotificationsGetprioritiesQueryParameters = {
  event: string;
};

export type GetApi10NotificationsGetscangroupsQueryParameters = {
  WebsiteId: string;
};

export type GetApi10NotificationsListQueryParameters = {
  page?: number;
  pageSize?: number;
};

export type PostApi10NotificationsNewBodyParameters =
  NewScanNotificationApiModel;

export type PostApi10NotificationsSetprioritiesBodyParameters =
  Array<NotificationPriorityPair>;

export type PostApi10NotificationsUpdateBodyParameters =
  UpdateScanNotificationApiModel;

export type PostApi10ScanpoliciesDeleteBodyParameters = string;

export type GetApi10ScanpoliciesGetQueryParameters = {
  name: string;
};

export type GetApi10ScanpoliciesListQueryParameters = {
  page?: number;
  pageSize?: number;
};

export type PostApi10ScanpoliciesNewBodyParameters = NewScanPolicySettingModel;

export type PostApi10ScanpoliciesUpdateBodyParameters =
  UpdateScanPolicySettingModel;

export type PostApi10ScanprofilesDeleteBodyParameters = string;

export type GetApi10ScanprofilesGetQueryParameters = {
  name: string;
};

export type GetApi10ScanprofilesListQueryParameters = {
  page?: number;
  pageSize?: number;
};

export type PostApi10ScanprofilesNewBodyParameters = SaveScanProfileApiModel;

export type PostApi10ScanprofilesUpdateBodyParameters = SaveScanProfileApiModel;

export type PostApi10ScansCancelBodyParameters = string;

export type GetApi10ScansCustomReportQueryParameters = {
  excludeIgnoreds?: boolean;
  id: string;
  onlyConfirmedVulnerabilities?: boolean;
  onlyUnconfirmedVulnerabilities?: boolean;
  reportName?: string;
  reportFormat?: string;
};

export type PostApi10ScansDeleteBodyParameters = Array<string>;

export type GetApi10ScansDownloadscanfileQueryParameters = {
  scanId: string;
};

export type PostApi10ScansIncrementalBodyParameters = IncrementalApiModel;

export type GetApi10ScansListQueryParameters = {
  page?: number;
  pageSize?: number;
};

export type GetApi10ScansListbystateQueryParameters = {
  scanTaskState: string;
  targetUrlCriteria?: string;
  page?: number;
  pageSize?: number;
  startDate?: string;
  endDate?: string;
};

export type GetApi10ScansListbystatechangedQueryParameters = {
  startDate: string;
  endDate?: string;
  page?: number;
  pageSize?: number;
};

export type GetApi10ScansListbywebsiteQueryParameters = {
  websiteUrl?: string;
  targetUrl?: string;
  page?: number;
  pageSize?: number;
  initiatedDateSortType?: string;
};

export type GetApi10ScansListScheduledQueryParameters = {
  page?: number;
  pageSize?: number;
};

export type PostApi10ScansNewBodyParameters = NewScanTaskApiModel;

export type PostApi10ScansNewfromscanBodyParameters = string;

export type PostApi10ScansNewgroupscanBodyParameters = NewGroupScanApiModel;

export type PostApi10ScansNewwithprofileBodyParameters =
  NewScanTaskWithProfileApiModel;

export type PostApi10ScansPauseBodyParameters = string;

export type GetApi10ScansReportQueryParameters = {
  contentFormat?: string;
  excludeResponseData?: boolean;
  format: string;
  id?: string;
  type?: string;
  onlyConfirmedIssues?: boolean;
  onlyUnconfirmedIssues?: boolean;
  excludeAddressedIssues?: boolean;
};

export type PostApi10ScansResumeBodyParameters = string;

export type PostApi10ScansRetestBodyParameters = BaseScanApiModel;

export type PostApi10ScansScheduleBodyParameters = NewScheduledScanApiModel;

export type PostApi10ScansScheduleIncrementalBodyParameters =
  NewScheduledIncrementalScanApiModel;

export type PostApi10ScansSchedulewithprofileBodyParameters =
  NewScheduledWithProfileApiModel;

export type PostApi10ScansTestScanProfileCredentialsBodyParameters =
  TestScanProfileCredentialsRequestModel;

export type PostApi10ScansUnscheduleBodyParameters = string;

export type PostApi10ScansUpdateScheduledBodyParameters =
  UpdateScheduledScanApiModel;

export type PostApi10ScansUpdateScheduledIncrementalBodyParameters =
  UpdateScheduledIncrementalScanApiModel;

export type PostApi10ScansVerifyformauthBodyParameters =
  FormAuthenticationVerificationApiModel;

export type GetApi10TeammembersGetapitokenQueryParameters = {
  email: string;
};

export type GetApi10TeammembersGetbyemailQueryParameters = {
  email: string;
};

export type GetApi10TeammembersListQueryParameters = {
  page?: number;
  pageSize?: number;
};

export type PostApi10TeammembersNewBodyParameters = NewUserApiModel;

export type PostApi10TeammembersUpdateBodyParameters = UpdateUserApiModel;

export type GetApi10TechnologiesListQueryParameters = {
  webSiteName?: string;
  technologyName?: string;
  page?: number;
  pageSize?: number;
};

export type GetApi10TechnologiesOutofdatetechnologiesQueryParameters = {
  webSiteName?: string;
  technologyName?: string;
  page?: number;
  pageSize?: number;
};

export type GetApi10VulnerabilityListQueryParameters = {
  reportPolicyId?: string;
};

export type GetApi10VulnerabilityTemplateQueryParameters = {
  type: string;
  reportPolicyId?: string;
};

export type PostApi10WebsitegroupsDeleteBodyParameters =
  DeleteWebsiteGroupApiModel;

export type GetApi10WebsitegroupsGetQueryParameters = {
  query: string;
};

export type GetApi10WebsitegroupsListQueryParameters = {
  page?: number;
  pageSize?: number;
};

export type PostApi10WebsitegroupsNewBodyParameters = NewWebsiteGroupApiModel;

export type PostApi10WebsitegroupsUpdateBodyParameters =
  UpdateWebsiteGroupApiModel;

export type PostApi10WebsitesDeleteBodyParameters = DeleteWebsiteApiModel;

export type GetApi10WebsitesGetQueryParameters = {
  query: string;
};

export type GetApi10WebsitesGetwebsitesbygroupQueryParameters = {
  query: string;
  page?: number;
  pageSize?: number;
};

export type GetApi10WebsitesListQueryParameters = {
  page?: number;
  pageSize?: number;
};

export type PostApi10WebsitesNewBodyParameters = NewWebsiteApiModel;

export type PostApi10WebsitesSendverificationemailBodyParameters = string;

export type PostApi10WebsitesStartverificationBodyParameters =
  StartVerificationApiModel;

export type PostApi10WebsitesUpdateBodyParameters = UpdateWebsiteApiModel;

export type GetApi10WebsitesVerificationfileQueryParameters = {
  websiteUrl: string;
};

export type PostApi10WebsitesVerifyBodyParameters = VerifyApiModel;

export interface ApiResponse<T> extends Response {
  json(): Promise<T>;
}
export type RequestFactoryType = (
  path: string,
  query: any,
  body: any,
  formData: any,
  headers: any,
  method: string,
  configuration: any
) => Promise<ApiResponse<any>>;

export class NetsparkerCloud<T extends {} = {}> {
  protected configuration: T;

  protected requestFactory: RequestFactoryType;

  constructor(configuration: T, requestFactory: RequestFactoryType) {
    this.configuration = configuration;
    this.requestFactory = requestFactory;
  }

  GetApi10AccountLicense(): Promise<ApiResponse<AccountLicenseApiModel>> {
    const path = "/api/1.0/account/license";
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10AccountMe(): Promise<ApiResponse<UserHealthCheckApiModel>> {
    const path = "/api/1.0/account/me";
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10AgentgroupsDelete(
    body: PostApi10AgentgroupsDeleteBodyParameters
  ): Promise<ApiResponse<{}>> {
    const path = "/api/1.0/agentgroups/delete";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10AgentgroupsList(
    query: GetApi10AgentgroupsListQueryParameters
  ): Promise<ApiResponse<AgentGroupsListApiResult>> {
    const path = "/api/1.0/agentgroups/list";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10AgentgroupsNew(
    body: PostApi10AgentgroupsNewBodyParameters
  ): Promise<ApiResponse<AgentGroupModel>> {
    const path = "/api/1.0/agentgroups/new";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10AgentgroupsUpdate(
    body: PostApi10AgentgroupsUpdateBodyParameters
  ): Promise<ApiResponse<AgentGroupModel>> {
    const path = "/api/1.0/agentgroups/update";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10AgentsDelete(
    body: PostApi10AgentsDeleteBodyParameters
  ): Promise<ApiResponse<any | any | any | any>> {
    const path = "/api/1.0/agents/delete";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10AgentsList(
    query: GetApi10AgentsListQueryParameters
  ): Promise<ApiResponse<AgentListApiResult>> {
    const path = "/api/1.0/agents/list";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10AgentsSetstatus(
    body: PostApi10AgentsSetstatusBodyParameters
  ): Promise<ApiResponse<any | any>> {
    const path = "/api/1.0/agents/setstatus";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10AuditlogsExport(
    query: GetApi10AuditlogsExportQueryParameters
  ): Promise<ApiResponse<any | any>> {
    const path = "/api/1.0/auditlogs/export";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10AuthenticationprofilesDelete(
    body: PostApi10AuthenticationprofilesDeleteBodyParameters
  ): Promise<ApiResponse<string>> {
    const path = "/api/1.0/authenticationprofiles/delete";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10AuthenticationprofilesGetById(
    idPathParameter: string
  ): Promise<ApiResponse<AuthenticationProfileViewModel>> {
    let path = "/api/1.0/authenticationprofiles/get/{id}";
    path = path.replace("{id}", String(idPathParameter));
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10AuthenticationprofilesGetall(): Promise<
    ApiResponse<AuthenticationProfileViewModel>
  > {
    const path = "/api/1.0/authenticationprofiles/getall";
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10AuthenticationprofilesNew(
    body: PostApi10AuthenticationprofilesNewBodyParameters
  ): Promise<ApiResponse<AuthenticationProfileViewModel>> {
    const path = "/api/1.0/authenticationprofiles/new";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10AuthenticationprofilesUpdate(
    body: PostApi10AuthenticationprofilesUpdateBodyParameters
  ): Promise<ApiResponse<AuthenticationProfileViewModel>> {
    const path = "/api/1.0/authenticationprofiles/update";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10DiscoveryExclude(
    body: PostApi10DiscoveryExcludeBodyParameters
  ): Promise<ApiResponse<{}>> {
    const path = "/api/1.0/discovery/exclude";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10DiscoveryExport(
    query: GetApi10DiscoveryExportQueryParameters
  ): Promise<ApiResponse<File>> {
    const path = "/api/1.0/discovery/export";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10DiscoveryIgnore(
    body: PostApi10DiscoveryIgnoreBodyParameters
  ): Promise<ApiResponse<string>> {
    const path = "/api/1.0/discovery/ignore";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10DiscoveryIgnorebyfilter(
    query: GetApi10DiscoveryIgnorebyfilterQueryParameters
  ): Promise<ApiResponse<string>> {
    const path = "/api/1.0/discovery/ignorebyfilter";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10DiscoveryList(
    query: GetApi10DiscoveryListQueryParameters
  ): Promise<ApiResponse<DiscoveryServiceListApiResult>> {
    const path = "/api/1.0/discovery/list";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10DiscoveryListbyfilter(
    query: GetApi10DiscoveryListbyfilterQueryParameters
  ): Promise<ApiResponse<DiscoveryServiceListApiResult>> {
    const path = "/api/1.0/discovery/listbyfilter";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10DiscoverySettings(): Promise<ApiResponse<DiscoverySettingsApiModel>> {
    const path = "/api/1.0/discovery/settings";
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10DiscoveryUpdateSettings(
    body: PostApi10DiscoveryUpdateSettingsBodyParameters
  ): Promise<ApiResponse<DiscoverySettingsApiModel>> {
    const path = "/api/1.0/discovery/update-settings";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10IssuesAddressedissues(
    query: GetApi10IssuesAddressedissuesQueryParameters
  ): Promise<ApiResponse<IssueApiResult>> {
    const path = "/api/1.0/issues/addressedissues";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10IssuesAllissues(
    query: GetApi10IssuesAllissuesQueryParameters
  ): Promise<ApiResponse<IssueApiResult>> {
    const path = "/api/1.0/issues/allissues";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10IssuesGetById(
    idPathParameter: string
  ): Promise<ApiResponse<IssueApiModel>> {
    let path = "/api/1.0/issues/get/{id}";
    path = path.replace("{id}", String(idPathParameter));
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10IssuesGetvulnerabilitycontentById(
    idPathParameter: string
  ): Promise<ApiResponse<VulnerabilityContentApiModel>> {
    let path = "/api/1.0/issues/getvulnerabilitycontent/{id}";
    path = path.replace("{id}", String(idPathParameter));
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10IssuesReport(
    query: GetApi10IssuesReportQueryParameters
  ): Promise<ApiResponse<any | any | any>> {
    const path = "/api/1.0/issues/report";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10IssuesTodo(
    query: GetApi10IssuesTodoQueryParameters
  ): Promise<ApiResponse<IssueApiResult>> {
    const path = "/api/1.0/issues/todo";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10IssuesUpdate(
    body: PostApi10IssuesUpdateBodyParameters
  ): Promise<ApiResponse<any | any | any | any>> {
    const path = "/api/1.0/issues/update";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10IssuesWaitingforretest(
    query: GetApi10IssuesWaitingforretestQueryParameters
  ): Promise<ApiResponse<IssueApiResult>> {
    const path = "/api/1.0/issues/waitingforretest";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10NotificationsDelete(
    body: PostApi10NotificationsDeleteBodyParameters
  ): Promise<ApiResponse<any | any | any>> {
    const path = "/api/1.0/notifications/delete";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10NotificationsGetById(
    idPathParameter: string
  ): Promise<ApiResponse<ScanNotificationApiModel>> {
    let path = "/api/1.0/notifications/get/{id}";
    path = path.replace("{id}", String(idPathParameter));
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10NotificationsGetpriorities(
    query: GetApi10NotificationsGetprioritiesQueryParameters
  ): Promise<ApiResponse<ScanNotificationApiModel>> {
    const path = "/api/1.0/notifications/getpriorities";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10NotificationsGetscangroups(
    query: GetApi10NotificationsGetscangroupsQueryParameters
  ): Promise<ApiResponse<ScanNotificationScanTaskGroupApiModel>> {
    const path = "/api/1.0/notifications/getscangroups";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10NotificationsList(
    query: GetApi10NotificationsListQueryParameters
  ): Promise<ApiResponse<ScanNotificationListApiResult>> {
    const path = "/api/1.0/notifications/list";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10NotificationsNew(
    body: PostApi10NotificationsNewBodyParameters
  ): Promise<ApiResponse<ScanNotificationApiModel>> {
    const path = "/api/1.0/notifications/new";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10NotificationsSetpriorities(
    body: PostApi10NotificationsSetprioritiesBodyParameters
  ): Promise<ApiResponse<any | any>> {
    const path = "/api/1.0/notifications/setpriorities";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10NotificationsUpdate(
    body: PostApi10NotificationsUpdateBodyParameters
  ): Promise<ApiResponse<ScanNotificationApiModel>> {
    const path = "/api/1.0/notifications/update";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScanpoliciesDelete(
    body: PostApi10ScanpoliciesDeleteBodyParameters
  ): Promise<ApiResponse<any | any | any>> {
    const path = "/api/1.0/scanpolicies/delete";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10ScanpoliciesGet(
    query: GetApi10ScanpoliciesGetQueryParameters
  ): Promise<ApiResponse<ScanPolicySettingApiModel>> {
    const path = "/api/1.0/scanpolicies/get";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10ScanpoliciesGetById(
    idPathParameter: string
  ): Promise<ApiResponse<ScanPolicySettingApiModel>> {
    let path = "/api/1.0/scanpolicies/get/{id}";
    path = path.replace("{id}", String(idPathParameter));
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10ScanpoliciesList(
    query: GetApi10ScanpoliciesListQueryParameters
  ): Promise<ApiResponse<ScanPolicyListApiResult>> {
    const path = "/api/1.0/scanpolicies/list";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10ScanpoliciesNew(
    body: PostApi10ScanpoliciesNewBodyParameters
  ): Promise<ApiResponse<ScanPolicySettingApiModel>> {
    const path = "/api/1.0/scanpolicies/new";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScanpoliciesUpdate(
    body: PostApi10ScanpoliciesUpdateBodyParameters
  ): Promise<ApiResponse<ScanPolicySettingApiModel>> {
    const path = "/api/1.0/scanpolicies/update";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScanprofilesDelete(
    body: PostApi10ScanprofilesDeleteBodyParameters
  ): Promise<ApiResponse<string>> {
    const path = "/api/1.0/scanprofiles/delete";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10ScanprofilesGet(
    query: GetApi10ScanprofilesGetQueryParameters
  ): Promise<ApiResponse<SaveScanProfileApiModel>> {
    const path = "/api/1.0/scanprofiles/get";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10ScanprofilesGetById(
    idPathParameter: string
  ): Promise<ApiResponse<SaveScanProfileApiModel>> {
    let path = "/api/1.0/scanprofiles/get/{id}";
    path = path.replace("{id}", String(idPathParameter));
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10ScanprofilesList(
    query: GetApi10ScanprofilesListQueryParameters
  ): Promise<ApiResponse<ScanProfilesListApiResult>> {
    const path = "/api/1.0/scanprofiles/list";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10ScanprofilesNew(
    body: PostApi10ScanprofilesNewBodyParameters
  ): Promise<ApiResponse<SaveScanProfileApiModel>> {
    const path = "/api/1.0/scanprofiles/new";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScanprofilesUpdate(
    body: PostApi10ScanprofilesUpdateBodyParameters
  ): Promise<ApiResponse<SaveScanProfileApiModel>> {
    const path = "/api/1.0/scanprofiles/update";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScansCancel(
    body: PostApi10ScansCancelBodyParameters
  ): Promise<ApiResponse<string>> {
    const path = "/api/1.0/scans/cancel";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10ScansCustomReport(
    query: GetApi10ScansCustomReportQueryParameters
  ): Promise<ApiResponse<any | any | any>> {
    const path = "/api/1.0/scans/custom-report/";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10ScansDelete(
    body: PostApi10ScansDeleteBodyParameters
  ): Promise<ApiResponse<string>> {
    const path = "/api/1.0/scans/delete";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10ScansDetailById(
    idPathParameter: string
  ): Promise<ApiResponse<ScanTaskModel>> {
    let path = "/api/1.0/scans/detail/{id}";
    path = path.replace("{id}", String(idPathParameter));
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10ScansDownloadscanfile(
    query: GetApi10ScansDownloadscanfileQueryParameters
  ): Promise<ApiResponse<{}>> {
    const path = "/api/1.0/scans/downloadscanfile";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10ScansIncremental(
    body: PostApi10ScansIncrementalBodyParameters
  ): Promise<ApiResponse<ScanTaskModel>> {
    const path = "/api/1.0/scans/incremental";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10ScansList(
    query: GetApi10ScansListQueryParameters
  ): Promise<ApiResponse<ScanTaskListApiResult>> {
    const path = "/api/1.0/scans/list";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10ScansListbystate(
    query: GetApi10ScansListbystateQueryParameters
  ): Promise<ApiResponse<ScanTaskListApiResult>> {
    const path = "/api/1.0/scans/listbystate";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10ScansListbystatechanged(
    query: GetApi10ScansListbystatechangedQueryParameters
  ): Promise<ApiResponse<ScanTaskListApiResult>> {
    const path = "/api/1.0/scans/listbystatechanged";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10ScansListbywebsite(
    query: GetApi10ScansListbywebsiteQueryParameters
  ): Promise<ApiResponse<ScanTaskListApiResult>> {
    const path = "/api/1.0/scans/listbywebsite";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10ScansListScheduled(
    query: GetApi10ScansListScheduledQueryParameters
  ): Promise<ApiResponse<ScheduledScanListApiResult>> {
    const path = "/api/1.0/scans/list-scheduled";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10ScansNew(
    body: PostApi10ScansNewBodyParameters
  ): Promise<ApiResponse<Array<ScanTaskModel>>> {
    const path = "/api/1.0/scans/new";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScansNewfromscan(
    body: PostApi10ScansNewfromscanBodyParameters
  ): Promise<ApiResponse<ScanTaskModel>> {
    const path = "/api/1.0/scans/newfromscan";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScansNewgroupscan(
    body: PostApi10ScansNewgroupscanBodyParameters
  ): Promise<ApiResponse<Array<ScanTaskModel>>> {
    const path = "/api/1.0/scans/newgroupscan";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScansNewwithprofile(
    body: PostApi10ScansNewwithprofileBodyParameters
  ): Promise<ApiResponse<ScanTaskModel>> {
    const path = "/api/1.0/scans/newwithprofile";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScansPause(
    body: PostApi10ScansPauseBodyParameters
  ): Promise<ApiResponse<string>> {
    const path = "/api/1.0/scans/pause";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10ScansReport(
    query: GetApi10ScansReportQueryParameters
  ): Promise<ApiResponse<any | any | any>> {
    const path = "/api/1.0/scans/report/";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10ScansResultById(
    idPathParameter: string
  ): Promise<ApiResponse<Array<VulnerabilityModel>>> {
    let path = "/api/1.0/scans/result/{id}";
    path = path.replace("{id}", String(idPathParameter));
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10ScansResume(
    body: PostApi10ScansResumeBodyParameters
  ): Promise<ApiResponse<string>> {
    const path = "/api/1.0/scans/resume";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScansRetest(
    body: PostApi10ScansRetestBodyParameters
  ): Promise<ApiResponse<ScanTaskModel>> {
    const path = "/api/1.0/scans/retest";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScansSchedule(
    body: PostApi10ScansScheduleBodyParameters
  ): Promise<ApiResponse<UpdateScheduledScanModel>> {
    const path = "/api/1.0/scans/schedule";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScansScheduleIncremental(
    body: PostApi10ScansScheduleIncrementalBodyParameters
  ): Promise<ApiResponse<UpdateScheduledScanModel>> {
    const path = "/api/1.0/scans/schedule-incremental";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScansSchedulewithprofile(
    body: PostApi10ScansSchedulewithprofileBodyParameters
  ): Promise<ApiResponse<UpdateScheduledScanModel>> {
    const path = "/api/1.0/scans/schedulewithprofile";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10ScansStatusById(
    idPathParameter: string
  ): Promise<ApiResponse<ApiScanStatusModel>> {
    let path = "/api/1.0/scans/status/{id}";
    path = path.replace("{id}", String(idPathParameter));
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10ScansTestScanProfileCredentials(
    body: PostApi10ScansTestScanProfileCredentialsBodyParameters
  ): Promise<ApiResponse<TestScanProfileCredentialsRequestModel>> {
    const path = "/api/1.0/scans/test-scan-profile-credentials";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScansUnschedule(
    body: PostApi10ScansUnscheduleBodyParameters
  ): Promise<ApiResponse<any | any>> {
    const path = "/api/1.0/scans/unschedule";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScansUpdateScheduled(
    body: PostApi10ScansUpdateScheduledBodyParameters
  ): Promise<ApiResponse<UpdateScheduledScanApiModel>> {
    const path = "/api/1.0/scans/update-scheduled";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScansUpdateScheduledIncremental(
    body: PostApi10ScansUpdateScheduledIncrementalBodyParameters
  ): Promise<ApiResponse<UpdateScheduledIncrementalScanApiModel>> {
    const path = "/api/1.0/scans/update-scheduled-incremental";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10ScansVerifyformauth(
    body: PostApi10ScansVerifyformauthBodyParameters
  ): Promise<ApiResponse<AuthVerificationApiResult>> {
    const path = "/api/1.0/scans/verifyformauth";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10TeammembersDeleteById(
    idPathParameter: string
  ): Promise<ApiResponse<string>> {
    let path = "/api/1.0/teammembers/delete/{id}";
    path = path.replace("{id}", String(idPathParameter));
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10TeammembersGetById(
    idPathParameter: string
  ): Promise<ApiResponse<UserApiModel>> {
    let path = "/api/1.0/teammembers/get/{id}";
    path = path.replace("{id}", String(idPathParameter));
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10TeammembersGetapitoken(
    query: GetApi10TeammembersGetapitokenQueryParameters
  ): Promise<ApiResponse<UserApiTokenModel>> {
    const path = "/api/1.0/teammembers/getapitoken";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10TeammembersGetbyemail(
    query: GetApi10TeammembersGetbyemailQueryParameters
  ): Promise<ApiResponse<UserApiModel>> {
    const path = "/api/1.0/teammembers/getbyemail";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10TeammembersGettimezones(): Promise<ApiResponse<TimezoneApiModel>> {
    const path = "/api/1.0/teammembers/gettimezones";
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10TeammembersList(
    query: GetApi10TeammembersListQueryParameters
  ): Promise<ApiResponse<UserListApiResult>> {
    const path = "/api/1.0/teammembers/list";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10TeammembersNew(
    body: PostApi10TeammembersNewBodyParameters
  ): Promise<ApiResponse<{} | UserApiModel>> {
    const path = "/api/1.0/teammembers/new";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10TeammembersUpdate(
    body: PostApi10TeammembersUpdateBodyParameters
  ): Promise<ApiResponse<UserApiModel>> {
    const path = "/api/1.0/teammembers/update";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10TechnologiesList(
    query: GetApi10TechnologiesListQueryParameters
  ): Promise<ApiResponse<TechnologyListApiResult>> {
    const path = "/api/1.0/technologies/list";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10TechnologiesOutofdatetechnologies(
    query: GetApi10TechnologiesOutofdatetechnologiesQueryParameters
  ): Promise<ApiResponse<TechnologyListApiResult>> {
    const path = "/api/1.0/technologies/outofdatetechnologies";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10VulnerabilityList(
    query: GetApi10VulnerabilityListQueryParameters
  ): Promise<ApiResponse<Array<VulnerabilityTemplate>>> {
    const path = "/api/1.0/vulnerability/list";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10VulnerabilityTemplate(
    query: GetApi10VulnerabilityTemplateQueryParameters
  ): Promise<ApiResponse<VulnerabilityTemplate>> {
    const path = "/api/1.0/vulnerability/template";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10VulnerabilityTypes(): Promise<ApiResponse<Array<string>>> {
    const path = "/api/1.0/vulnerability/types";
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10WebsitegroupsDelete(
    body: PostApi10WebsitegroupsDeleteBodyParameters
  ): Promise<ApiResponse<string>> {
    const path = "/api/1.0/websitegroups/delete";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10WebsitegroupsDeleteById(
    idPathParameter: string
  ): Promise<ApiResponse<string>> {
    let path = "/api/1.0/websitegroups/delete/{id}";
    path = path.replace("{id}", String(idPathParameter));
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10WebsitegroupsGet(
    query: GetApi10WebsitegroupsGetQueryParameters
  ): Promise<ApiResponse<WebsiteGroupApiModel>> {
    const path = "/api/1.0/websitegroups/get";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10WebsitegroupsGetById(
    idPathParameter: string
  ): Promise<ApiResponse<WebsiteGroupApiModel>> {
    let path = "/api/1.0/websitegroups/get/{id}";
    path = path.replace("{id}", String(idPathParameter));
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10WebsitegroupsList(
    query: GetApi10WebsitegroupsListQueryParameters
  ): Promise<ApiResponse<WebsiteGroupListApiResult>> {
    const path = "/api/1.0/websitegroups/list";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10WebsitegroupsNew(
    body: PostApi10WebsitegroupsNewBodyParameters
  ): Promise<ApiResponse<WebsiteGroupApiModel>> {
    const path = "/api/1.0/websitegroups/new";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10WebsitegroupsUpdate(
    body: PostApi10WebsitegroupsUpdateBodyParameters
  ): Promise<ApiResponse<WebsiteGroupApiModel>> {
    const path = "/api/1.0/websitegroups/update";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10WebsitesDelete(
    body: PostApi10WebsitesDeleteBodyParameters
  ): Promise<ApiResponse<string>> {
    const path = "/api/1.0/websites/delete";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10WebsitesGet(
    query: GetApi10WebsitesGetQueryParameters
  ): Promise<ApiResponse<WebsiteApiModel>> {
    const path = "/api/1.0/websites/get";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10WebsitesGetById(
    idPathParameter: string
  ): Promise<ApiResponse<WebsiteApiModel>> {
    let path = "/api/1.0/websites/get/{id}";
    path = path.replace("{id}", String(idPathParameter));
    return this.requestFactory(
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10WebsitesGetwebsitesbygroup(
    query: GetApi10WebsitesGetwebsitesbygroupQueryParameters
  ): Promise<ApiResponse<WebsiteListApiResult>> {
    const path = "/api/1.0/websites/getwebsitesbygroup";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  GetApi10WebsitesList(
    query: GetApi10WebsitesListQueryParameters
  ): Promise<ApiResponse<WebsiteListApiResult>> {
    const path = "/api/1.0/websites/list";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10WebsitesNew(
    body: PostApi10WebsitesNewBodyParameters
  ): Promise<ApiResponse<WebsiteApiModel>> {
    const path = "/api/1.0/websites/new";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10WebsitesSendverificationemail(
    body: PostApi10WebsitesSendverificationemailBodyParameters
  ): Promise<ApiResponse<SendVerificationEmailModel>> {
    const path = "/api/1.0/websites/sendverificationemail";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10WebsitesStartverification(
    body: PostApi10WebsitesStartverificationBodyParameters
  ): Promise<ApiResponse<StartVerificationResult>> {
    const path = "/api/1.0/websites/startverification";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  PostApi10WebsitesUpdate(
    body: PostApi10WebsitesUpdateBodyParameters
  ): Promise<ApiResponse<WebsiteApiModel>> {
    const path = "/api/1.0/websites/update";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }

  GetApi10WebsitesVerificationfile(
    query: GetApi10WebsitesVerificationfileQueryParameters
  ): Promise<ApiResponse<any | any>> {
    const path = "/api/1.0/websites/verificationfile";
    return this.requestFactory(
      path,
      query,
      undefined,
      undefined,
      undefined,
      "GET",
      this.configuration
    );
  }

  PostApi10WebsitesVerify(
    body: PostApi10WebsitesVerifyBodyParameters
  ): Promise<ApiResponse<string>> {
    const path = "/api/1.0/websites/verify";
    return this.requestFactory(
      path,
      undefined,
      body,
      undefined,
      undefined,
      "POST",
      this.configuration
    );
  }
}
