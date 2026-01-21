using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Xml.Linq;

namespace AdvancedSenderRouting
{
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
}
