using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Xml.Linq;

namespace AdvancedSenderRouting
{
    /// <summary>
    /// Log level for file logging
    /// </summary>
    public enum LogLevel
    {
        None = 0,
        Error = 1,
        Warning = 2,
        Info = 3,
        Debug = 4,
        Verbose = 5
    }

    /// <summary>
    /// Configuration for Advanced Sender Based Routing Agent.
    /// Supports advanced routing rules with sender and recipient conditions,
    /// wildcard matching, and send-as-alias features.
    /// </summary>
    public class RoutingConfiguration
    {
        private const string ConfigFileName = "routing-config.xml";

        private bool _enableSendAsAlias = true;
        private bool _enableSenderBasedRouting = true;
        private bool _bypassLocalRecipients = true;
        private bool _routeByHeaderFrom = false;
        private bool _validateProxyAddresses = true;
        private bool _blockIfNoAlias = false;
        private List<RoutingRule> _routingRules = new List<RoutingRule>();
        private List<string> _localDomains = new List<string>();

        // Logging settings
        private bool _enableFileLogging = false;
        private LogLevel _logLevel = LogLevel.Info;
        private string _logPath = null;
        private int _maxLogFileSizeMB = 10;
        private int _maxLogFiles = 5;

        public bool EnableSendAsAlias
        {
            get { return _enableSendAsAlias; }
            set { _enableSendAsAlias = value; }
        }

        public bool EnableSenderBasedRouting
        {
            get { return _enableSenderBasedRouting; }
            set { _enableSenderBasedRouting = value; }
        }

        public bool BypassLocalRecipients
        {
            get { return _bypassLocalRecipients; }
            set { _bypassLocalRecipients = value; }
        }

        /// <summary>
        /// If true, use the From header (P2/alias) for routing rule matching.
        /// If false (default), use envelope sender (P1/primary address).
        /// </summary>
        public bool RouteByHeaderFrom
        {
            get { return _routeByHeaderFrom; }
            set { _routeByHeaderFrom = value; }
        }

        /// <summary>
        /// If true, validate that sender has the alias domain in their proxy addresses.
        /// Uses existing From header to determine if user selected a valid alias.
        /// </summary>
        public bool ValidateProxyAddresses
        {
            get { return _validateProxyAddresses; }
            set { _validateProxyAddresses = value; }
        }

        /// <summary>
        /// If true and ValidateProxyAddresses is true, block external email if sender
        /// doesn't have an alias in the rule's SendAsAlias domain.
        /// </summary>
        public bool BlockIfNoAlias
        {
            get { return _blockIfNoAlias; }
            set { _blockIfNoAlias = value; }
        }

        /// <summary>
        /// Enable logging to text file
        /// </summary>
        public bool EnableFileLogging
        {
            get { return _enableFileLogging; }
            set { _enableFileLogging = value; }
        }

        /// <summary>
        /// Log level (None, Error, Warning, Info, Debug, Verbose)
        /// </summary>
        public LogLevel FileLogLevel
        {
            get { return _logLevel; }
            set { _logLevel = value; }
        }

        /// <summary>
        /// Path to log file directory. If null, uses Exchange transport logs folder.
        /// </summary>
        public string LogPath
        {
            get { return _logPath; }
            set { _logPath = value; }
        }

        /// <summary>
        /// Maximum log file size in megabytes before rotation
        /// </summary>
        public int MaxLogFileSizeMB
        {
            get { return _maxLogFileSizeMB; }
            set { _maxLogFileSizeMB = value > 0 ? value : 10; }
        }

        /// <summary>
        /// Maximum number of log files to keep (rotation)
        /// </summary>
        public int MaxLogFiles
        {
            get { return _maxLogFiles; }
            set { _maxLogFiles = value > 0 ? value : 5; }
        }

        public List<string> LocalDomains
        {
            get { return _localDomains; }
            set { _localDomains = value; }
        }

        public List<RoutingRule> RoutingRules
        {
            get { return _routingRules; }
            set { _routingRules = value; }
        }

        /// <summary>
        /// Loads configuration from XML file located alongside the agent DLL.
        /// </summary>
        public static RoutingConfiguration Load()
        {
            var config = new RoutingConfiguration();

            try
            {
                var assemblyPath = Assembly.GetExecutingAssembly().Location;
                var assemblyDir = Path.GetDirectoryName(assemblyPath);
                var configPath = Path.Combine(assemblyDir, ConfigFileName);

                LogInfo(string.Format("Loading configuration from: {0}", configPath));

                if (!File.Exists(configPath))
                {
                    LogWarning(string.Format("Configuration file not found at {0}. Using defaults.", configPath));
                    return config;
                }

                var doc = XDocument.Load(configPath);
                var root = doc.Root;

                if (root == null)
                    return config;

                // Parse feature toggles
                var settings = root.Element("settings");
                if (settings != null)
                {
                    var enableSendAsAliasElement = settings.Element("enableSendAsAlias");
                    var enableSenderBasedRoutingElement = settings.Element("enableSenderBasedRouting");
                    var bypassLocalRecipientsElement = settings.Element("bypassLocalRecipients");
                    var routeByHeaderFromElement = settings.Element("routeByHeaderFrom");
                    var validateProxyAddressesElement = settings.Element("validateProxyAddresses");
                    var blockIfNoAliasElement = settings.Element("blockIfNoAlias");

                    config.EnableSendAsAlias = ParseBool(
                        enableSendAsAliasElement != null ? enableSendAsAliasElement.Value : null,
                        true);
                    config.EnableSenderBasedRouting = ParseBool(
                        enableSenderBasedRoutingElement != null ? enableSenderBasedRoutingElement.Value : null,
                        true);
                    config.BypassLocalRecipients = ParseBool(
                        bypassLocalRecipientsElement != null ? bypassLocalRecipientsElement.Value : null,
                        true);
                    config.RouteByHeaderFrom = ParseBool(
                        routeByHeaderFromElement != null ? routeByHeaderFromElement.Value : null,
                        false);
                    config.ValidateProxyAddresses = ParseBool(
                        validateProxyAddressesElement != null ? validateProxyAddressesElement.Value : null,
                        true);
                    config.BlockIfNoAlias = ParseBool(
                        blockIfNoAliasElement != null ? blockIfNoAliasElement.Value : null,
                        false);
                }

                // Parse logging settings
                var loggingElement = root.Element("logging");
                if (loggingElement != null)
                {
                    var enableFileLoggingElement = loggingElement.Element("enableFileLogging");
                    var logLevelElement = loggingElement.Element("logLevel");
                    var logPathElement = loggingElement.Element("logPath");
                    var maxLogFileSizeMBElement = loggingElement.Element("maxLogFileSizeMB");
                    var maxLogFilesElement = loggingElement.Element("maxLogFiles");

                    config.EnableFileLogging = ParseBool(
                        enableFileLoggingElement != null ? enableFileLoggingElement.Value : null,
                        false);

                    if (logLevelElement != null && !string.IsNullOrEmpty(logLevelElement.Value))
                    {
                        LogLevel level;
                        if (Enum.TryParse(logLevelElement.Value, true, out level))
                        {
                            config.FileLogLevel = level;
                        }
                    }

                    if (logPathElement != null && !string.IsNullOrEmpty(logPathElement.Value))
                    {
                        config.LogPath = logPathElement.Value;
                    }

                    if (maxLogFileSizeMBElement != null)
                    {
                        int size;
                        if (int.TryParse(maxLogFileSizeMBElement.Value, out size) && size > 0)
                        {
                            config.MaxLogFileSizeMB = size;
                        }
                    }

                    if (maxLogFilesElement != null)
                    {
                        int count;
                        if (int.TryParse(maxLogFilesElement.Value, out count) && count > 0)
                        {
                            config.MaxLogFiles = count;
                        }
                    }
                }

                // Parse local domains for bypass
                var localDomainsElement = root.Element("localDomains");
                if (localDomainsElement != null)
                {
                    foreach (var domainElement in localDomainsElement.Elements("domain"))
                    {
                        var domain = domainElement.Value;
                        if (!string.IsNullOrEmpty(domain))
                        {
                            config.LocalDomains.Add(domain.ToLowerInvariant().TrimStart('@'));
                            LogInfo(string.Format("Loaded local domain: {0}", domain));
                        }
                    }
                }

                // Parse routing rules
                var rulesElement = root.Element("routingRules");
                if (rulesElement != null)
                {
                    foreach (var ruleElement in rulesElement.Elements("rule"))
                    {
                        var nameAttr = ruleElement.Attribute("name");
                        var enabledAttr = ruleElement.Attribute("enabled");
                        var senderDomainAttr = ruleElement.Attribute("senderDomain");
                        var senderAddressAttr = ruleElement.Attribute("senderAddress");
                        var recipientDomainAttr = ruleElement.Attribute("recipientDomain");
                        var recipientAddressAttr = ruleElement.Attribute("recipientAddress");
                        var addressSpaceAttr = ruleElement.Attribute("addressSpace");
                        var smartHostAttr = ruleElement.Attribute("smartHost");
                        var sendAsAliasAttr = ruleElement.Attribute("sendAsAlias");

                        var rule = new RoutingRule();
                        rule.Name = nameAttr != null ? nameAttr.Value : null;
                        rule.Enabled = ParseBool(enabledAttr != null ? enabledAttr.Value : null, true);
                        rule.SenderDomain = senderDomainAttr != null ? senderDomainAttr.Value : null;
                        rule.SenderAddress = senderAddressAttr != null ? senderAddressAttr.Value : null;
                        rule.RecipientDomain = recipientDomainAttr != null ? recipientDomainAttr.Value : null;
                        rule.RecipientAddress = recipientAddressAttr != null ? recipientAddressAttr.Value : null;
                        rule.ConnectorAddressSpace = addressSpaceAttr != null ? addressSpaceAttr.Value : null;
                        rule.SmartHost = smartHostAttr != null ? smartHostAttr.Value : null;
                        rule.SendAsAlias = sendAsAliasAttr != null ? sendAsAliasAttr.Value : null;

                        if (!string.IsNullOrEmpty(rule.SenderDomain) || !string.IsNullOrEmpty(rule.SenderAddress))
                        {
                            config.RoutingRules.Add(rule);
                            LogInfo(string.Format("Loaded rule: Name={0}, Enabled={1}, SenderDomain={2}, SenderAddress={3}, RecipientDomain={4}, RecipientAddress={5}, AddressSpace={6}, SendAsAlias={7}",
                                rule.Name ?? "(unnamed)",
                                rule.Enabled,
                                rule.SenderDomain ?? "(none)",
                                rule.SenderAddress ?? "(none)",
                                rule.RecipientDomain ?? "(any)",
                                rule.RecipientAddress ?? "(any)",
                                rule.ConnectorAddressSpace ?? "(none)",
                                rule.SendAsAlias ?? "(none)"));
                        }
                    }
                }

                LogInfo(string.Format("Configuration loaded: SendAsAlias={0}, SenderBasedRouting={1}, Rules={2}",
                    config.EnableSendAsAlias,
                    config.EnableSenderBasedRouting,
                    config.RoutingRules.Count));
            }
            catch (Exception ex)
            {
                LogError(string.Format("Error loading configuration: {0}", ex.Message));
            }

            return config;
        }

        private static bool ParseBool(string value, bool defaultValue)
        {
            bool result;
            if (bool.TryParse(value, out result))
                return result;
            return defaultValue;
        }

        private static void LogInfo(string message)
        {
            try
            {
                System.Diagnostics.EventLog.WriteEntry(
                    "MSExchangeTransport",
                    "AdvancedSenderRouting:" + message,
                    System.Diagnostics.EventLogEntryType.Information,
                    1000);
            }
            catch { }
        }

        private static void LogWarning(string message)
        {
            try
            {
                System.Diagnostics.EventLog.WriteEntry(
                    "MSExchangeTransport",
                    "AdvancedSenderRouting:" + message,
                    System.Diagnostics.EventLogEntryType.Warning,
                    1002);
            }
            catch { }
        }

        private static void LogError(string message)
        {
            try
            {
                System.Diagnostics.EventLog.WriteEntry(
                    "MSExchangeTransport",
                    "AdvancedSenderRouting:" + message,
                    System.Diagnostics.EventLogEntryType.Error,
                    1001);
            }
            catch { }
        }
    }

    /// <summary>
    /// Represents an advanced routing rule with sender and recipient conditions.
    /// </summary>
    public class RoutingRule
    {
        private string _name;
        private string _senderDomain;
        private string _senderAddress;
        private string _recipientDomain;
        private string _recipientAddress;
        private string _connectorAddressSpace;
        private string _smartHost;
        private string _sendAsAlias;
        private bool _enabled = true;

        /// <summary>
        /// Rule name for identification
        /// </summary>
        public string Name
        {
            get { return _name; }
            set { _name = value; }
        }

        /// <summary>
        /// Whether the rule is enabled
        /// </summary>
        public bool Enabled
        {
            get { return _enabled; }
            set { _enabled = value; }
        }

        /// <summary>
        /// Sender domain to match (e.g., "@sales.company.com" or "sales.company.com")
        /// </summary>
        public string SenderDomain
        {
            get { return _senderDomain; }
            set { _senderDomain = value; }
        }

        /// <summary>
        /// Exact sender address to match (e.g., "specific.user@company.com")
        /// </summary>
        public string SenderAddress
        {
            get { return _senderAddress; }
            set { _senderAddress = value; }
        }

        /// <summary>
        /// Recipient domain to match (e.g., "@partner.com" or "partner.com")
        /// If not specified, matches all recipients.
        /// </summary>
        public string RecipientDomain
        {
            get { return _recipientDomain; }
            set { _recipientDomain = value; }
        }

        /// <summary>
        /// Exact recipient address to match (e.g., "orders@partner.com")
        /// If not specified, matches all recipients.
        /// </summary>
        public string RecipientAddress
        {
            get { return _recipientAddress; }
            set { _recipientAddress = value; }
        }

        /// <summary>
        /// Address space that matches a Send Connector's configured address space.
        /// </summary>
        public string ConnectorAddressSpace
        {
            get { return _connectorAddressSpace; }
            set { _connectorAddressSpace = value; }
        }

        /// <summary>
        /// Smart host IP for reference (used when creating connectors).
        /// </summary>
        public string SmartHost
        {
            get { return _smartHost; }
            set { _smartHost = value; }
        }

        /// <summary>
        /// Alias domain or address to use as From header.
        /// Use "@domain.com" to construct from sender's local part.
        /// Use "user@domain.com" for exact address.
        /// </summary>
        public string SendAsAlias
        {
            get { return _sendAsAlias; }
            set { _sendAsAlias = value; }
        }

        /// <summary>
        /// Checks if this rule matches the given sender address.
        /// Supports wildcards: * (any characters) and ? (single character).
        /// </summary>
        public bool MatchesSender(string senderAddress)
        {
            if (string.IsNullOrEmpty(senderAddress))
                return false;

            senderAddress = senderAddress.ToLowerInvariant();

            // Check exact sender address match first (with wildcard support)
            if (!string.IsNullOrEmpty(SenderAddress))
            {
                return WildcardMatch(senderAddress, SenderAddress.ToLowerInvariant());
            }

            // Check sender domain match (with wildcard support)
            if (!string.IsNullOrEmpty(SenderDomain))
            {
                var pattern = SenderDomain.ToLowerInvariant();

                // If pattern has wildcards, match full address
                if (pattern.Contains("*") || pattern.Contains("?"))
                {
                    // Prepend *@ if pattern doesn't start with * to match any local part
                    if (!pattern.StartsWith("*"))
                    {
                        pattern = "*@" + pattern.TrimStart('@');
                    }
                    return WildcardMatch(senderAddress, pattern);
                }

                // Standard domain suffix match
                var domain = pattern.StartsWith("@") ? pattern : "@" + pattern;
                return senderAddress.EndsWith(domain, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        /// <summary>
        /// Checks if this rule matches the given recipient address.
        /// Supports wildcards: * (any characters) and ? (single character).
        /// </summary>
        public bool MatchesRecipient(string recipientAddress)
        {
            // If no recipient conditions, match all
            if (string.IsNullOrEmpty(RecipientDomain) && string.IsNullOrEmpty(RecipientAddress))
                return true;

            if (string.IsNullOrEmpty(recipientAddress))
                return false;

            recipientAddress = recipientAddress.ToLowerInvariant();

            // Check exact recipient address match first (with wildcard support)
            if (!string.IsNullOrEmpty(RecipientAddress))
            {
                return WildcardMatch(recipientAddress, RecipientAddress.ToLowerInvariant());
            }

            // Check recipient domain match (with wildcard support)
            if (!string.IsNullOrEmpty(RecipientDomain))
            {
                var pattern = RecipientDomain.ToLowerInvariant();

                // If pattern has wildcards, match full address
                if (pattern.Contains("*") || pattern.Contains("?"))
                {
                    // Prepend *@ if pattern doesn't start with * to match any local part
                    if (!pattern.StartsWith("*"))
                    {
                        pattern = "*@" + pattern.TrimStart('@');
                    }
                    return WildcardMatch(recipientAddress, pattern);
                }

                // Standard domain suffix match
                var domain = pattern.StartsWith("@") ? pattern : "@" + pattern;
                return recipientAddress.EndsWith(domain, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        /// <summary>
        /// Matches a string against a pattern with wildcards.
        /// * matches any sequence of characters (including empty).
        /// ? matches any single character.
        /// </summary>
        private static bool WildcardMatch(string input, string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
                return string.IsNullOrEmpty(input);

            // Convert wildcard pattern to regex
            // Escape regex special chars except * and ?
            var regexPattern = "^";
            foreach (char c in pattern)
            {
                switch (c)
                {
                    case '*':
                        regexPattern += ".*";
                        break;
                    case '?':
                        regexPattern += ".";
                        break;
                    case '.':
                    case '+':
                    case '^':
                    case '$':
                    case '(':
                    case ')':
                    case '[':
                    case ']':
                    case '{':
                    case '}':
                    case '|':
                    case '\\':
                        regexPattern += "\\" + c;
                        break;
                    default:
                        regexPattern += c;
                        break;
                }
            }
            regexPattern += "$";

            try
            {
                return System.Text.RegularExpressions.Regex.IsMatch(
                    input,
                    regexPattern,
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// File logger with rotation support
    /// </summary>
    public class FileLogger
    {
        private static FileLogger _instance;
        private static readonly object _lock = new object();
        private RoutingConfiguration _config;
        private string _logFilePath;
        private bool _initialized = false;

        private FileLogger() { }

        public static FileLogger Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        if (_instance == null)
                        {
                            _instance = new FileLogger();
                        }
                    }
                }
                return _instance;
            }
        }

        public void Initialize(RoutingConfiguration config)
        {
            lock (_lock)
            {
                _config = config;

                if (!config.EnableFileLogging)
                {
                    _initialized = false;
                    return;
                }

                try
                {
                    // Determine log path
                    string logDir = config.LogPath;

                    if (string.IsNullOrEmpty(logDir))
                    {
                        // Default to Exchange transport logs folder
                        var exchangePath = Environment.GetEnvironmentVariable("ExchangeInstallPath");
                        if (!string.IsNullOrEmpty(exchangePath))
                        {
                            logDir = Path.Combine(exchangePath, "TransportRoles", "Logs", "AdvancedSenderRouting");
                        }
                        else
                        {
                            // Fallback to agent directory
                            var assemblyPath = Assembly.GetExecutingAssembly().Location;
                            logDir = Path.Combine(Path.GetDirectoryName(assemblyPath), "Logs");
                        }
                    }

                    // Create directory if it doesn't exist
                    if (!Directory.Exists(logDir))
                    {
                        Directory.CreateDirectory(logDir);
                    }

                    _logFilePath = Path.Combine(logDir, "AdvancedSenderRouting.log");
                    _initialized = true;

                    // Log initialization
                    WriteLog(LogLevel.Info, "File logging initialized. Path: " + _logFilePath);
                }
                catch (Exception ex)
                {
                    _initialized = false;
                    // Log to event log as fallback
                    try
                    {
                        System.Diagnostics.EventLog.WriteEntry(
                            "MSExchangeTransport",
                            "AdvancedSenderRouting: Failed to initialize file logging: " + ex.Message,
                            System.Diagnostics.EventLogEntryType.Warning,
                            1002);
                    }
                    catch { }
                }
            }
        }

        public void Log(LogLevel level, string message)
        {
            if (!_initialized || _config == null || !_config.EnableFileLogging)
                return;

            if (level > _config.FileLogLevel || _config.FileLogLevel == LogLevel.None)
                return;

            WriteLog(level, message);
        }

        public void LogError(string message)
        {
            Log(LogLevel.Error, message);
        }

        public void LogWarning(string message)
        {
            Log(LogLevel.Warning, message);
        }

        public void LogInfo(string message)
        {
            Log(LogLevel.Info, message);
        }

        public void LogDebug(string message)
        {
            Log(LogLevel.Debug, message);
        }

        public void LogVerbose(string message)
        {
            Log(LogLevel.Verbose, message);
        }

        private void WriteLog(LogLevel level, string message)
        {
            lock (_lock)
            {
                try
                {
                    // Check file size and rotate if needed
                    RotateLogIfNeeded();

                    // Write log entry
                    var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                    var logEntry = string.Format("[{0}] [{1}] {2}", timestamp, level.ToString().ToUpper(), message);

                    using (var writer = new StreamWriter(_logFilePath, true))
                    {
                        writer.WriteLine(logEntry);
                    }
                }
                catch
                {
                    // Silently fail - don't break email flow for logging issues
                }
            }
        }

        private void RotateLogIfNeeded()
        {
            try
            {
                if (!File.Exists(_logFilePath))
                    return;

                var fileInfo = new FileInfo(_logFilePath);
                var maxSizeBytes = _config.MaxLogFileSizeMB * 1024L * 1024L;

                if (fileInfo.Length < maxSizeBytes)
                    return;

                // Rotate files
                var logDir = Path.GetDirectoryName(_logFilePath);
                var logName = Path.GetFileNameWithoutExtension(_logFilePath);
                var logExt = Path.GetExtension(_logFilePath);

                // Delete oldest file if at max
                var oldestFile = Path.Combine(logDir, string.Format("{0}.{1}{2}", logName, _config.MaxLogFiles, logExt));
                if (File.Exists(oldestFile))
                {
                    File.Delete(oldestFile);
                }

                // Rotate existing files
                for (int i = _config.MaxLogFiles - 1; i >= 1; i--)
                {
                    var currentFile = Path.Combine(logDir, string.Format("{0}.{1}{2}", logName, i, logExt));
                    var nextFile = Path.Combine(logDir, string.Format("{0}.{1}{2}", logName, i + 1, logExt));

                    if (File.Exists(currentFile))
                    {
                        File.Move(currentFile, nextFile);
                    }
                }

                // Rename current log to .1
                var firstBackup = Path.Combine(logDir, string.Format("{0}.1{1}", logName, logExt));
                File.Move(_logFilePath, firstBackup);
            }
            catch
            {
                // Silently fail rotation
            }
        }
    }
}
