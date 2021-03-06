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
import { CustomFieldModel } from './customFieldModel';
import { IssueApiModelCvssVector } from './issueApiModelCvssVector';
import { IssueHistoryApiModel } from './issueHistoryApiModel';
import { IssueRequestContentParametersApiModel } from './issueRequestContentParametersApiModel';
import { VersionIssue } from './versionIssue';
import { VulnerabilityClassification } from './vulnerabilityClassification';
/**
* Represents a class that carries vulnerability information.
*/
export declare class IssueApiModel {
    /**
    * Gets or sets the name of the assignee.
    */
    'assigneeName'?: string;
    /**
    * Gets or sets the first seen date.
    */
    'firstSeenDate'?: string;
    /**
    * Gets or sets the identifier.
    */
    'id'?: string;
    /**
    * Gets or sets a value indicating whether this vulnerability is addressed.
    */
    'isAddressed'?: boolean;
    /**
    * Gets or sets a value indicating whether this vulnerability is detected by shark/acusensor.
    */
    'isDetectedByShark'?: boolean;
    /**
    * Gets or sets a value indicating whether this vulnerability is present.
    */
    'isPresent'?: boolean;
    /**
    * Gets or sets the last seen date.
    */
    'lastSeenDate'?: string;
    /**
    * Gets or sets the severity.
    */
    'severity'?: IssueApiModel.SeverityEnum;
    /**
    * Gets or sets the state.
    */
    'state'?: string;
    /**
    * Gets or sets the title.
    */
    'title'?: string;
    /**
    * Gets or sets the URL.
    */
    'url'?: string;
    /**
    * Gets or sets a value indicating whether [vulnerability confirmed].
    */
    'latestVulnerabilityIsConfirmed'?: boolean;
    /**
    * Gets or sets the website identifier.
    */
    'websiteId'?: string;
    /**
    * Gets or sets the name of the website.
    */
    'websiteName'?: string;
    /**
    * Gets or sets the website root URL.
    */
    'websiteRootUrl'?: string;
    /**
    * Gets or sets the issue fix time.
    */
    'fixTimeInMinutes'?: number;
    /**
    * Gets or sets the certainty.
    */
    'certainty'?: number;
    /**
    * Gets the issue parameters.
    */
    'parameters'?: Array<IssueRequestContentParametersApiModel>;
    /**
    * Gets a detail of the vulerability.
    */
    'vulnerabilityDetail'?: string;
    /**
    * Gets a description of the impact of the associated vulnerability.
    */
    'impact'?: string;
    /**
    * Gets a description of the actions of the associated vulnerability.
    */
    'actions'?: string;
    /**
    * Gets a description of the skills of the associated vulnerability.
    */
    'skills'?: string;
    /**
    * Gets a description of the remedy of the associated vulnerability.
    */
    'remedy'?: string;
    /**
    * Gets a description of the remedy references of the associated vulnerability.
    */
    'remedyReferences'?: string;
    /**
    * Gets a description of the external of the associated vulnerability.
    */
    'externalReferences'?: string;
    /**
    * Gets a description of the proof of concept for the associated vulnerability.
    */
    'proofOfConcept'?: string;
    /**
    * Gets a description of the proof of concept for the associated vulnerability.
    */
    'customData'?: string;
    /**
    * Gets a collection of the vulnerability.
    */
    'customFields'?: Array<CustomFieldModel>;
    /**
    * Gets the classification links
    */
    'classificationLinks'?: Array<string>;
    /**
    * Gets the CVSS 3.0 vector string.
    */
    'cvssVectorString'?: string;
    /**
    * Gets the CVSS 3.1 vector string.
    */
    'cvss31VectorString'?: string;
    /**
    * Gets or sets the Vulnerability Type. This is an unique discriminator for vulnerabilities.
    */
    'type'?: IssueApiModel.TypeEnum;
    'classification'?: VulnerabilityClassification;
    'cvssVector'?: IssueApiModelCvssVector;
    /**
    * Gets the version issues
    */
    'versionIssues'?: Array<VersionIssue>;
    /**
    * Gets or sets a value indicating whether this vulnerability is waiting for retest
    */
    'isRetest'?: boolean;
    /**
    * Gets or sets a value indicating whether this vulnerability is todo.
    */
    'isTodo'?: boolean;
    /**
    * Gets or set the latest scan identifier.
    */
    'latestScanId'?: string;
    /**
    * Gets or sets the History.
    */
    'history'?: Array<IssueHistoryApiModel>;
    /**
    * Tags
    */
    'tags'?: Array<string>;
    static discriminator: string | undefined;
    static attributeTypeMap: Array<{
        name: string;
        baseName: string;
        type: string;
    }>;
    static getAttributeTypeMap(): {
        name: string;
        baseName: string;
        type: string;
    }[];
}
export declare namespace IssueApiModel {
    enum SeverityEnum {
        BestPractice,
        Information,
        Low,
        Medium,
        High,
        Critical
    }
    enum TypeEnum {
        Custom,
        None,
        HighlyPossibleSqlInjection,
        Xss,
        PossibleXss,
        PermanentXss,
        PossiblePermanentXss,
        InternalServerError,
        ForbiddenResource,
        PassiveVulns,
        PossibleBlindSqlInjection,
        NtlmAuthrizationRequired,
        BasicAuthorisationRequired,
        DigestAuthorizationRequired,
        ClearTextBasicAuth,
        ConfirmedBlindSqlInjection,
        PossibleSqlInjection,
        ConfirmedSqlInjection,
        FileUploadFound,
        AutoCompleteEnabled,
        PasswordOverHttp,
        PasswordFormOverHttp,
        InternalIpLeakage,
        CookieNotMarkedAsSecure,
        CookieNotMarkedAsHttpOnly,
        ConfirmedBooleanSqlInjection,
        PossibleBooleanSqlInjection,
        PasswordToHttp,
        CommandInjection,
        BlindCommandInjection,
        PossibleBlindCommandInjection,
        HeaderInjection,
        MySqlIdentified,
        MsSqlIdentified,
        MsAccessIdentified,
        DbConnectedAsAdmin,
        AspNetIdentified,
        AspNetVersionDisclosure,
        IisDirectoryListing,
        ApacheDirectoryListing,
        TomcatDirectoryListing,
        PhpSourceCodeDisclosure,
        AspNetSourceCodeDisclosure,
        GenericSourceCodeDisclosure,
        PossibleInternalUnixPathLeakage,
        MsOfficeDocumentInformationDisclosure,
        PhpInfoIdentified,
        PossibleLocalFileInclusion,
        OracleIdentified,
        PostgreSqlIdentified,
        HighPossibilityLfi,
        Lfi,
        PossibleInternalWindowsPathLeakage,
        EmailDisclosure,
        SocialSecurityNumberDisclosure,
        ApacheVersionDisclosure,
        TomcatVersionDisclosure,
        PhpVersionDisclosure,
        IisVersionDisclosure,
        WebLogicVersionDisclosure,
        LighttpdVersionDisclosure,
        SharePointVersionDisclosure,
        ApacheCoyoteVersionDisclosure,
        OracleApplicationServerVersionDisclosure,
        OpenSslVersionDisclosure,
        ApacheModuleVersionDisclosure,
        PerlVersionDisclosure,
        FrontPageVersionDisclosure,
        PythonVersionDisclosure,
        JavaServletVersionDisclosure,
        SitemapIdentified,
        CrossDomainXml,
        RobotsIdentified,
        SpecialCase,
        SpecialCaseNoCookies,
        SpecialCaseNoBasicAuthentication,
        ApacheServerStatus,
        ApacheServerInfo,
        ClientAccessPolicy,
        OpenCrossDomainXml,
        OpenClientAccessPolicy,
        HighPossibleBooleanSqlInjection,
        DatabaseErrorMessages,
        ProgrammingErrorMessages,
        ApacheMultiViewsEnabled,
        BackupFileFound,
        BackupSourceCodeFound,
        TraceTrackIdentified,
        TraceaxdFound,
        ElmahaxdFound,
        AspNetDebugEnabled,
        LfiCodeInclusion,
        AspNetStackTrace,
        SvnDisclosure,
        GitDisclosure,
        CvsDisclosure,
        Rfi,
        PossibleRfi,
        PossibleCi,
        XssViaRfi,
        RceAsp,
        PossibleRceAsp,
        RcePhp,
        PossibleRcePhp,
        RcePerl,
        PossibleRcePerl,
        ViewStateMacNotEnabled,
        ViewStateNotEncrypted,
        ViewStateAnalyzer,
        OpenRedirect,
        TomcatExceptionReport,
        DjangoStackTraceDisclosure,
        Struts2DevModeEnabled,
        AspNetDirectoryListing,
        MySqlUsernameDisclosure,
        MsSqlUsernameDisclosure,
        WinUsernameDisclosure,
        RceViaLfi,
        XssProtectionDisabled,
        MdbFound,
        WeakCredentials,
        PythonStackTraceDisclosure,
        ColdFusionStackTraceDisclosure,
        DefaultIis7Page,
        DefaultIis6Page,
        DefaultApachePage,
        SinatraStackTraceDisclosure,
        SqliteFound,
        OutlookFileFound,
        DsStoreFileFound,
        FrameInjection,
        DefaultTomcatPage,
        TomcatSourceCodeDisclosure,
        WebBackdoorIdentified,
        PassiveWebBackdoorIdentified,
        PossibleAdminFile,
        PossibleConfigFile,
        PossibleReadmeFile,
        PossibleInstallationFile,
        PossibleLogFile,
        PossibleSqlFile,
        PossibleTestFile,
        TomcatOutOfDate,
        ApacheOutOfDate,
        MsSqlOutOfDate,
        MySqlOutOfDate,
        PhpOutOfDate,
        OpenSslOutOfDate,
        RedirectBodyTooLarge,
        RedirectTwoResponses,
        SslVersion2Support,
        WeakCiphersDetected,
        AnonAuthDetected,
        WeakSignatureAlgorithmDetected,
        InvalidSslCertificate,
        SslVersion3Support,
        IntermediateWeakSignatureAlgorithmDetected,
        MvcVersionDisclosure,
        MongrelVersionDisclosure,
        NginxVersionDisclosure,
        MySqldoSDetected,
        GrailsStackTraceDisclosure,
        PossibleElInjection,
        ElInjection,
        ApacheMyFacesStackTraceDisclosure,
        PasswordOverQuerystring,
        ColdFusionSourceCodeDisclosure,
        AwStatsIdentified,
        MintIdentified,
        PiwikIdentified,
        WsftpLogFileIdentified,
        WebConfigIdentified,
        LigHttpdDirectoryListing,
        NginxDirectoryListing,
        LiteSpeedDirectoryListing,
        GenericEmailDisclosure,
        DefaultIis8Page,
        ShellScriptIdentified,
        PossibleDatabaseConnectionStringIdentified,
        UncServerAndShareDisclosure,
        HstsNotEnabled,
        HstsMaxAge,
        HstsViaHttp,
        HstsErrors,
        WordPressOutOfDate,
        DrupalOutOfDate,
        JoomlaOutOfDate,
        MediaWikiOutOfDate,
        MovableTypeOutOfDate,
        OscommerceOutOfDate,
        PhpBbOutOfDate,
        TWikiOutOfDate,
        WordPressIdentified,
        DrupalIdentified,
        JoomlaIdentified,
        MediaWikiIdentified,
        MovableTypeIdentified,
        OscommerceIdentified,
        PhpBbIdentified,
        TWikiIdentified,
        RceRorXml,
        RceRorJson,
        PossibleRceRorXml,
        PossibleRceRorJson,
        VersionDisclosureModSsl,
        PhpmyAdminIdentified,
        WebalizerIdentified,
        VersionDisclosureRuby,
        VersionDisclosureWebrick,
        OptionsMethodEnabled,
        WebDavEnabled,
        WebDavDirectoryHasWritePermissions,
        CodeExecutionViaWebDav,
        WebDavDirectoryListing,
        CsrfDetected,
        CsrfInLoginFormDetected,
        CookieLeakageInAntiCsrfTokenDetected,
        MisconfiguredFrame,
        InsecureFrameExternal,
        DomBasedXss,
        NuSoapVersionDisclosure,
        NuSoapOutOfDate,
        AutoCompleteEnabledPasswordField,
        NginxOutOfDate,
        PerlSourceCodeDisclosure,
        PythonSourceCodeDisclosure,
        RubySourceCodeDisclosure,
        JavaSourceCodeDisclosure,
        OpenSslHeartbleedVulnerability,
        NginxIdentified,
        ApacheIdentified,
        JavaStackTraceDisclosure,
        MissingXFrameOptionsHeader,
        MissingContentTypeHeader,
        CommandInjectionShellshock,
        PossibleReflectedFileDownload,
        InsecureJsonpEndpoint,
        InsecureReflectedContent,
        MisconfiguredAccessControlOrigin,
        PassiveMixedContent,
        Teapot,
        PossibleXxe,
        Xxe,
        UnrestrictedFileUpload,
        CodeExecutionViaFileUpload,
        PossibleCreditCardDisclosure,
        RsaPrivateKeyDetected,
        RceInHttpSys,
        OpenRedirectInPost,
        FormHijacking,
        BaseTagHijacking,
        WindowsShortFilename,
        RorDatabaseConfigurationFileDetected,
        RorDevelopmentModeEnabled,
        RorVersionDisclosure,
        RubyGemsVersionDisclosure,
        RubyGemsOutOfDate,
        RubyOutOfDate,
        RorOutOfDate,
        PythonOutOfDate,
        PerlOutOfDate,
        DjangoDebugModeEnabled,
        DjangoVersionDisclosure,
        DjangoOutOfDate,
        PhpLiteAdminIdentified,
        AdminerIdentified,
        MicrosoftIisLogFileIdentified,
        PhpMoAdminIdentified,
        DbNinjaIdentified,
        LaravelEnvironmentConfigurationFileDetected,
        LaravelDebugModeEnabled,
        LaravelStackTraceDisclosure,
        SublimeSftpConfigFileDetected,
        RorStackTraceDisclosure,
        JqueryOutOfDate,
        JqueryMigrateOutOfDate,
        JqueryMobileOutOfDate,
        JqueryUiDialogOutOfDate,
        JqueryUiAutocompleteOutOfDate,
        JqueryUiTooltipOutOfDate,
        PrettyPhotoOutOfDate,
        JplayerOutOfDate,
        YuiOutOfDate,
        PrototypejsOutOfDate,
        EmberOutOfDate,
        DojoOutOfDate,
        AngularjsOutOfDate,
        BackbonejsOutOfDate,
        MustachejsOutOfDate,
        HandlebarsjsOutOfDate,
        EasyXdmOutOfDate,
        PluploadOutOfDate,
        DomPurifyOutOfDate,
        DwrOutOfDate,
        InsecureHttpUsage,
        OpenCartIdentified,
        OpenCartOutOfDate,
        MissingXssProtectionHeader,
        VideojsOutOfDate,
        TlsVersion1Support,
        SameSiteCookieNotImplemented,
        ReverseTabnabbing,
        SubResourceIntegrityNotImplemented,
        SubResourceIntegrityHashInvalid,
        PossibleSsrf,
        OutOfBandSqlInjection,
        OutOfBandXxe,
        BlindXss,
        OutOfBandRfi,
        OutOfBandRcePhp,
        OutOfBandCommandInjection,
        SsrfAws,
        PossibleSsrfAws,
        SsrfElmah,
        PossibleSsrfElmah,
        SsrfTrace,
        PossibleSsrfTrace,
        OutOfBandRceAsp,
        OutOfBandRcePerl,
        DomBasedOpenRedirect,
        DeprecatedCspHeader,
        CspNotImplemented,
        InvalidCspMetaTag,
        InvalidCspInsructionInMeta,
        CspKeywordUsedAsTarget,
        UnsafeCspInstructionDetected,
        NonceDetectedInCsp,
        NoScriptTagDetectedWithNonce,
        SameNonceValueDetected,
        DefaultSrcUsedInCsp,
        InsecureReportUriDetectedInCsp,
        ReportUriWithDifferentHostDetectedInCsp,
        WildcardDetectedInScheme,
        WildcardDetectedInDomain,
        WildcardDetectedInPort,
        UnsupportedHashDetectedInScriptInstruction,
        InsecureNonceValueDetected,
        SsrfElmahMvc,
        PossibleSsrfElmahMvc,
        DeprecatedHeaderDetectedWithCspHeader,
        InvalidNonceDetectedInCsp,
        NoScriptTagDetectedWithHash,
        DataCspDirectiveDetected,
        CspReportOnlyHeaderDetectedWithoutReportUri,
        CspReportOnlyUsedInMeta,
        SingleHeaderMultipleCookies,
        OutOfBandRceRoRXml,
        OutOfBandRceRoRJson,
        ObjectSrcNotUsed,
        ApacheMultiChoiceEnabled,
        HttpOrHttpsDetectedOnScriptSrc,
        InsecureTargetUriDetectedInCsp,
        PossibleTimeBasedSsrf,
        PossibleBlindXss,
        PossibleSsrfSsh,
        PossibleSsrfMySql,
        RceApacheStruts,
        PossibleRceApacheStruts,
        ControllableCookie,
        ReferrerPolicyNotImplemented,
        ReferrerPolicyReferrerLeakToSameProtocol,
        ReferrerPolicyOriginLeakToCrossSite,
        ReferrerPolicySameProtocolLeak,
        ReferrerPolicyCrossOriginLeak,
        ReferrerPolicyStrictCrossOriginLeak,
        ReferrerPolicyCrossSiteReferrerLeak,
        ReferrerPolicyUnknown,
        ReferrerPolicyFallbackMissing,
        MsSqlDatabaseNameDisclosure,
        MySqlDatabaseNameDisclosure,
        ActiveMixedContent,
        MixedContentScript,
        MixedContentResource,
        KnockoutjsOutOfDate,
        BootstrapjsOutOfDate,
        TypeaheadjsOutOfDate,
        FootablejsOutOfDate,
        SortablejsOutOfDate,
        ImagePickerOutOfDate,
        JqueryValidationOutOfDate,
        AspNetSignalROutOfDate,
        Select2OutOfDate,
        MomentjsOutOfDate,
        Html5ShivOutOfDate,
        IonRangeSliderOutOfDate,
        JsTreeOutOfDate,
        ModernizrOutOfDate,
        RespondjsOutOfDate,
        FuelUxOutOfDate,
        BootboxOutOfDate,
        KnockoutMappingOutOfDate,
        JqueryMaskOutOfDate,
        Bootstrap3DateTimePickerOutOfDate,
        BootstrapToggleOutOfDate,
        JavaScriptCookieOutOfDate,
        MixedContentFont,
        MixedContentXhrEndpoint,
        PossibleRceNodeJs,
        RceNodeJs,
        ReactOutOfDate,
        PossibleSsrfApacheServerStatus,
        DefaultIis85Page,
        DefaultIis100Page,
        DefaultIis75Page,
        DefaultIis7XPage,
        CkeditorOutOfDate,
        WordPressSetupConfigurationFile,
        PossibleOutOfBandCommandInjectionStruts052,
        OutOfBandCommandInjectionStruts053,
        LighttpdOutOfDate,
        PostgreSqlOutOfDate,
        RceApacheStrutsS0253,
        PossibleRceApacheStrutsS0253,
        RceApacheStrutsS2046,
        PossibleRceApacheStrutsS2046,
        RceApacheStrutsS2045,
        PossibleRceApacheStrutsS2045,
        AbanteCartIdentified,
        AbanteCartOutOfDate,
        AmpacheIdentified,
        AmpacheOutOfDate,
        AtutorIdentified,
        AtutorOutOfDate,
        ChamiloIdentified,
        ChamiloOutOfDate,
        ClarolineIdentified,
        ClarolineOutOfDate,
        CollabtiveIdentified,
        CollabtiveOutOfDate,
        Concrete5Identified,
        Concrete5OutOfDate,
        CoppermineIdentified,
        CoppermineOutOfDate,
        CubeCartIdentified,
        CubeCartOutOfDate,
        DokuWikiIdentified,
        DokuWikiOutOfDate,
        DotClearIdentified,
        DotClearOutOfDate,
        E107Identified,
        E107OutOfDate,
        FamilyConnectionsIdentified,
        FamilyConnectionsOutOfDate,
        FluxBbIdentified,
        FluxBbOutOfDate,
        FormToolsIdentified,
        FormToolsOutOfDate,
        FrontAccountingIdentified,
        FrontAccountingOutOfDate,
        GibbonEduIdentified,
        GibbonEduOutOfDate,
        HeskIdentified,
        HeskOutOfDate,
        LimeSurveyIdentified,
        LimeSurveyOutOfDate,
        LiveHelperChatIdentified,
        LiveHelperChatOutOfDate,
        LogaholicIdentified,
        LogaholicOutOfDate,
        MibewMessengerIdentified,
        MibewMessengerOutOfDate,
        ModXIdentified,
        ModXOutOfDate,
        MoodleIdentified,
        MoodleOutOfDate,
        MyBbIdentified,
        MyBbOutOfDate,
        OmekaIdentified,
        OmekaOutOfDate,
        OsClassIdentified,
        OsClassOutOfDate,
        OsTicketIdentified,
        OsTicketOutOfDate,
        PrestashopIdentified,
        PrestashopOutOfDate,
        EspoCrmIdentified,
        EspoCrmOutOfDate,
        ElggIdentified,
        ElggOutOfDate,
        PhorumIdentified,
        PhorumOutOfDate,
        PhpFusionIdentified,
        PhpFusionOutOfDate,
        PhpAddressBookIdentified,
        PhpAddressBookOutOfDate,
        PhpListIdentified,
        PhpListOutOfDate,
        PmWikiIdentified,
        PmWikiOutOfDate,
        PodcastGeneratorIdentified,
        PodcastGeneratorOutOfDate,
        ProjectSendIdentified,
        ProjectSendOutOfDate,
        Question2AnswerIdentified,
        Question2AnswerOutOfDate,
        RukovoditelIdentified,
        RukovoditelOutOfDate,
        SeoPanelIdentified,
        SeoPanelOutOfDate,
        SerendipityIdentified,
        SerendipityOutOfDate,
        TcExamIdentified,
        TcExamOutOfDate,
        VanillaForumsIdentified,
        VanillaForumsOutOfDate,
        WebErpIdentified,
        WebErpOutOfDate,
        WeBidIdentified,
        WeBidOutOfDate,
        XoopsIdentified,
        XoopsOutOfDate,
        YetiForceCrmIdentified,
        YetiForceCrmOutOfDate,
        YourlsIdentified,
        YourlsOutOfDate,
        ZenCartIdentified,
        ZenCartOutOfDate,
        ZenPhotoIdentified,
        ZenPhotoOutOfDate,
        PiwigoIdentified,
        PiwigoOutOfDate,
        ZurmoIdentified,
        ZurmoOutOfDate,
        OwnCloudIdentified,
        OwnCloudOutOfDate,
        PhpMyFaqIdentified,
        PhpMyFaqOutOfDate,
        RoundcubeIdentified,
        RoundcubeOutOfDate,
        ZikulaIdentified,
        ZikulaOutOfDate,
        WeakRobotOracleDetected,
        StrongRobotOracleDetected,
        ZeptojsOutOfDate,
        HammerjsOutOfDate,
        VuejsOutOfDate,
        PhaserOutOfDate,
        ChartjsOutOfDate,
        RamdaOutOfDate,
        RevealJsOutOfDate,
        PixiJsOutOfDate,
        FabricJsOutOfDate,
        SemanticUiOutOfDate,
        LeafletOutOfDate,
        PossibleOutOfBandCommandInjection,
        FoundationOutOfDate,
        ThreeJsOutOfDate,
        PdfJsOutOfDate,
        ExpressJsIdentified,
        PossibleSsti,
        Ssti,
        PossibleCodeExecutionViaSsti,
        CodeExecutionViaSsti,
        PossibleCodeExecutionViaSstiTwig,
        CodeExecutionViaSstiTwig,
        PossibleCodeExecutionViaSstiMako,
        CodeExecutionViaSstiMako,
        PossibleCodeExecutionViaSstiSmarty,
        CodeExecutionViaSstiSmarty,
        PossibleCodeExecutionViaSstiNunjucks,
        CodeExecutionViaSstiNunjucks,
        PossibleCodeExecutionViaSstiJade,
        CodeExecutionViaSstiJade,
        PossibleSstiDot,
        SstiDot,
        PossibleCodeExecutionViaSstiDot,
        CodeExecutionViaSstiDot,
        PossibleSstiEjs,
        SstiEjs,
        PossibleCodeExecutionViaSstiEjs,
        CodeExecutionViaSstiEjs,
        PossibleCodeExecutionViaSstiMarko,
        CodeExecutionViaSstiMarko,
        PossibleCodeExecutionViaSstiTornado,
        CodeExecutionViaSstiTornado,
        PossibleCodeExecutionViaSstiFreeMarker,
        CodeExecutionViaSstiFreeMarker,
        PossibleSstiVelocity,
        SstiVelocity,
        PossibleCodeExecutionViaSstiVelocity,
        CodeExecutionViaSstiVelocity,
        PossibleSstiErb,
        SstiErb,
        PossibleCodeExecutionViaSstiErb,
        CodeExecutionViaSstiErb,
        PossibleCodeExecutionViaSstiSlim,
        CodeExecutionViaSstiSlim,
        PossibleCodeExecutionViaSstiJinja,
        CodeExecutionViaSstiJinja,
        PossibleSstiFreeMarker,
        SstiFreeMarker,
        OutOfBandCodeExecutionViaSsti,
        OutOfBandCodeExecutionViaSstiMako,
        OutOfBandCodeExecutionViaSstiTornado,
        OutOfBandCodeExecutionViaSstiJinja,
        OutOfBandCodeExecutionViaSstiMarko,
        OutOfBandCodeExecutionViaSstiDot,
        OutOfBandCodeExecutionViaSstiNunjucks,
        OutOfBandCodeExecutionViaSstiJade,
        OutOfBandCodeExecutionViaSstiSmarty,
        ExpectCtIsMissing,
        ExpectCtShouldBeServedOverTls,
        ExpectCtReportOnlyModeIsEnabled,
        ExpectCtErrors,
        AuthenticationRequired,
        CaddyWebServerIdentified,
        AahGoServerIdentified,
        JbossApplicationServerIdentified,
        JbossVersionDisclosure,
        Ckeditor5OutOfDate,
        CakePhpIdentified,
        CakePhpStackTraceDisclosure,
        DefaultPageCakePhp,
        CakePhpVersionDisclosure,
        CakePhpOutOfDate,
        CherryPyVersionDisclosure,
        CherryPyOutOfDate,
        OutOfBandCodeExecutionViaSstiEjs,
        OutOfBandCodeExecutionViaSstiTwig,
        OutOfBandCodeExecutionViaSstiFreeMarker,
        OutOfBandCodeExecutionViaSstiVelocity,
        CherryPyStackTraceDisclosure,
        IntrojsOutOfDate,
        AxiosOutOfDate,
        Fingerprintjs2OutOfDate,
        XRegExpOutOfDate,
        DataTablesOutOfDate,
        LazyjsOutOfDate,
        FancyBoxOutOfDate,
        UnderscorejsOutOfDate,
        LightboxOutOfDate,
        JbossApplicationServerOutOfDate,
        SweetAlert2OutOfDate,
        LodashOutOfDate,
        BluebirdOutOfDate,
        PolymerOutOfDate,
        ReviveAdserverIdentified,
        ReviveAdserverOutOfDate,
        B2evolutionIdentified,
        B2evolutionOutOfDate,
        DolphinIdentified,
        DolphinOutOfDate,
        Ph7CmsIdentified,
        Ph7CmsOutOfDate,
        QdPmIdentified,
        QdPmOutOfDate,
        VtigerIdentified,
        VtigerOutOfDate,
        DolibarrIdentified,
        DolibarrOutOfDate,
        ClipBucketIdentified,
        ClipBucketOutOfDate,
        ContaoIdentified,
        ContaoOutOfDate,
        MisconfiguredXFrameOptionsHeader,
        RubyErrorDisclosure,
        WpEngineConfigurationFileDetected,
        SessionCookieNotMarkedAsSecure,
        PossibleHeaderInjection,
        OracleOutOfDate,
        TsWebIdentified,
        DrupalRce,
        MithrilOutOfDate,
        EfJsOutOfDate,
        MathJsOutOfDate,
        ListJsOutOfDate,
        RequireJsOutOfDate,
        RiotJsOutOfDate,
        InfernoOutOfDate,
        MarionetteJsOutOfDate,
        GsapOutOfDate,
        TravisYamlIdentified,
        UnicodeTransformationIssue,
        MalwareIdentified,
        RorFileContentDisclosure,
        AppSiteAssociationIdentified,
        OpenSearchIdentified,
        ServletSourceCodeDisclosure,
        JspSourceCodeDisclosure,
        HtaccessIdentified,
        RcePython,
        PossibleRcePython,
        OutOfBandRcePython,
        RceRuby,
        PossibleRceRuby,
        OutOfBandRceRuby,
        SwaggerJsonIdentified,
        SslNotImplemented,
        SecurityTxtIdentified,
        RceApacheStrutsS2016,
        PossibleRceApacheStrutsS2016,
        SlickOutOfDate,
        ScrollRevealOutOfDate,
        MathJaxOutOfDate,
        RickshawOutOfDate,
        HighchartsOutOfDate,
        SnapSvgOutOfDate,
        FlickityOutOfDate,
        D3JsOutOfDate,
        GoogleChartsOutOfDate,
        HiawathaVersionDisclosure,
        CherokeeVersionDisclosure,
        HiawathaOutOfDate,
        CherokeeOutOfDate,
        OracleWebLogicOutOfDate,
        WebCacheDeception,
        IisOutOfDate,
        ImmutablejsOutOfDate,
        AxwaySecureTransportDetected,
        MisconfiguredXFrameOptionsHeaderMultipleDirectives,
        TlsVersion11Support,
        PossibleSsrfOracleCloud,
        PossibleSsrfPacketCloud,
        ExtJsOutOfDate,
        PossibleHpp,
        PossibleBreachAttack,
        TelerikWebUiVersionDisclosure,
        TelerikWebUiOutOfDate,
        JavaVersionDisclosure,
        GlassfishVersionDisclosure,
        JavaOutOfDate,
        GlassfishOutOfDate,
        WafIdentified,
        AkamaiCdnIdentified,
        AzureCdnIdentified,
        GoogleCloudCdnIdentified,
        ArvanCloudCdnIdentified,
        FastlyCdnIdentified,
        IncapsulaCdnIdentified,
        SucuriCdnIdentified,
        NetlifyCdnIdentified,
        MaxCdnIdentified,
        KeyCdnIdentified,
        FirebladeCdnIdentified,
        AireeCdnIdentified,
        West263CdnIdentified,
        InstartCdnIdentified,
        QratorCdnIdentified,
        PowerCdnIdentified,
        Cdn77Identified,
        F5BigIpProxyIdentified,
        EnvoyProxyIdentified,
        CitrixNetScalerProxyIdentified,
        ApacheTrafficServerProxyIdentified,
        HaProxyIdentified,
        SkipperProxyIdentified,
        LoginPageIdentified,
        SameSiteCookieNotMarkedAsSecure,
        LiferayPortalIdentified,
        LiferayPortalOufOfDate,
        ApacheTrafficServerVersionDisclosure,
        ApacheTrafficServerOutOfDate,
        UndertowWebServerVersionDisclosure,
        UndertowWebServerOutOfDate,
        JenkinsVersionDisclosure,
        JenkinsOutOfDate,
        KestrelIdentified,
        TableauServerIdentified,
        BomgarIdentified,
        JolokiaVersionDisclosure,
        JolokiaOutOfDate,
        F5BigIpLocalFileInclusion,
        PossibleF5BigIpLocalFileInclusion,
        PossibleSstiPebble,
        SstiPebble,
        PossibleCodeExecutionViaSstiPebble,
        CodeExecutionViaSstiPebble,
        SugarCrmIdentified,
        SugarCrmOutOfDate,
        GrafanaVersionDisclosure,
        GrafanaOutOfDate,
        PossibleSstiJinJava,
        SstiJinJava,
        PossibleCodeExecutionViaSstiJinJava,
        CodeExecutionViaSstiJinJava,
        PossibleSstiAspNetRazor,
        SstiAspNetRazor,
        PossibleCodeExecutionViaSstiAspNetRazor,
        CodeExecutionViaSstiAspNetRazor,
        PhpMagicQuotesGpcDisabled,
        PhpRegisterGlobalsEnabled,
        PhpDisplayErrorsEnabled,
        PhpAllowUrlFopenEnabled,
        PhpAllowUrlIncludeEnabled,
        PhpSessionUseTransSidEnabled,
        PhpOpenBaseDirIsNotSet,
        PhpEnableDlEnabled,
        AspNetApplicationTraceEnabled,
        AspNetCookilessSessionStateEnabled,
        AspNetCookilessAuthenticationEnabled,
        AspNetNoSslAuth,
        AspNetLoginCredentialsPlainText,
        AspNetValidateRequestDisabled,
        AspNetViewStateUserKeyNotSet,
        JettyVersionDisclosure,
        TornadoWebServerVersionDisclosure,
        TracyDebuggingVersionDisclosure,
        AspNetCustomErrorsDisabled,
        WhoopsFrameworkIdentified,
        PhpUseOnlyCookiesIsDisabled,
        CrushFtpServerIdentified,
        RceWeblogic,
        WeblogicAuthenticationBypass,
        ArbitraryFileCreation,
        ArbitraryFileDeletion,
        WerkzeugIdentified,
        WerkzeugVersionDisclosure,
        WerkzeugOutOfDate,
        OpenRestyIdentified,
        OpenRestyVersionDisclosure,
        OpenRestyOutOfDate,
        LiteSpeedWebServerIdentified,
        TwistedWebHttpServerIdentified,
        TwistedWebHttpServerVersionDisclosure,
        TwistedWebHttpServerOutOfDate,
        NextJsReactFrameworkIdentified,
        NextJsReactFrameworkVersionDisclosure,
        NextJsReactFrameworkOutOfDate,
        DaiquiriVersionDisclosure,
        W3TotalCacheOutOfDate,
        W3TotalCacheIdentified,
        W3TotalCacheVersionDisclosure,
        PhusionPassengerIdentified,
        PhusionPassengerVersionDisclosure,
        PhusionPassengerOutOfDate,
        SqlInjectionIast,
        LfiIast,
        RcePhpIast,
        HeaderInjectionIast,
        CommandInjectionIast,
        AxwaySecureTransportIdentified,
        AxwaySecureTransportVersionDisclosure,
        AxwaySecureTransportOutOfDate,
        BurpCollaboratorServerIdentified,
        ResinApplicationServerIdentified,
        ResinApplicationServerVersionDisclosure,
        ResinApplicationServerOutOfDate,
        TracSoftwareProjectManagementToolIdentified,
        TracSoftwareProjectManagementToolVersionDisclosure,
        TracSoftwareProjectManagementToolOutOfDate,
        TornadoWebServerIdentified,
        TornadoWebServerOutOfDate,
        JettyWebServerIdentified,
        JettyWebServerOutOfDate,
        TracyDebuggingToolOutOfDate,
        ZopeWebServerVersionDisclosure,
        ZopeWebServerOutOfDate,
        ArtifactoryIdentified,
        ArtifactoryVersionDisclosure,
        ArtifactoryOutOfDate,
        JBossEapIdentified,
        WildFlyIdentified,
        GunicornIdentified,
        GunicornVersionDisclosure,
        GunicornOutOfDate,
        JBossCsIdentified,
        WebSealIdentified,
        OracleHttpIdentified,
        SonicWallSslvpnIdentified,
        PloneCmsIdentified,
        PloneCmsVersionDisclosure,
        PloneCmsOutOfDate,
        GlassFishIdentified,
        IbrtcIdentified,
        IbmrtcVersionDisclosure,
        IbmrtcOutOfDate,
        NexusIdentified,
        NexusVersionDisclosure,
        NexusOutOfDate,
        IbmhttpServerIdentified,
        IbmhttpServerVersionDisclosure,
        IbmhttpServerOutOfDate,
        PythonWsgIserverIdentified,
        PythonWsgIserverVersionDisclosure,
        PythonWsgIserverOutOfDate,
        PlayFrameworkIdentified,
        VarnishCacheIdentified,
        RestletFrameworkIdentified,
        RestletFrameworkVersionDisclosure,
        RestletFrameworkOutOfDate,
        ZopeWebServerIdentified,
        WebSealOutOfDate,
        WebSealVersionDisclosure,
        CowboyIdentified,
        CowboyOutOfDate,
        CowboyVersionDisclosure,
        LiferayPortalVersionDisclosure,
        RevokedSslCertificate,
        SslCertificateHostnameMismatch,
        SslCertificateSignedByUntrustedRoot,
        ExpiredSslCertificate,
        JwtNoneAlgorithmAllowed,
        JwtSignatureNotChecked,
        JwtInsecureSecretDetected,
        JwtSqlInjectionInKid,
        ZshHistoryFileDetected,
        JwtPathTraversalInKid,
        JwtJkuHijack,
        JwtJkuForgeryWithOpenRedirect,
        DaiquiriIdentified,
        Typo3CmsIdentified,
        Typo3CmsOutOfDate,
        SslCertificateAboutToExpire,
        MagentoIdentified,
        MagentoOutOfDate,
        DaiquiriOutOfDate
    }
}
