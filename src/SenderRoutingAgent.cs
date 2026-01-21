using System;
using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Routing;
using Microsoft.Exchange.Data.Transport.Email;
using Microsoft.Exchange.Data.Mime;

namespace AdvancedSenderRouting
{
    /// <summary>
    /// Advanced Sender Based Routing Agent for Microsoft Exchange 2019.
    ///
    /// Features:
    /// 1. Send-As-Alias: Preserves sender alias (proxy address) in outbound emails
    /// 2. Sender-Based Routing: Routes emails through specific connectors based on sender domain
    /// 3. Advanced Rules: Supports sender AND recipient conditions with wildcards (* and ?)
    /// 4. Per-Recipient Routing: Different routing for different recipients in the same message
    /// </summary>
    public sealed class AdvancedSenderRoutingAgent : RoutingAgent
    {
        private readonly RoutingConfiguration _config;
        private readonly FileLogger _fileLogger;

        public AdvancedSenderRoutingAgent(RoutingConfiguration config)
        {
            if (config == null)
                throw new ArgumentNullException("config");

            _config = config;

            // Initialize file logger
            _fileLogger = FileLogger.Instance;
            _fileLogger.Initialize(config);

            // Subscribe to OnResolvedMessage event - fires after recipient resolution
            OnResolvedMessage += ResolvedMessageHandler;
        }

        private void ResolvedMessageHandler(ResolvedMessageEventSource source, QueuedMessageEventArgs args)
        {
            try
            {
                var mailItem = args.MailItem;

                // Get sender address for rule matching
                // Use From header (P2) if RouteByHeaderFrom is enabled, otherwise envelope sender (P1)
                string senderAddress = null;
                string envelopeSender = null;

                if (mailItem.FromAddress != null)
                {
                    envelopeSender = mailItem.FromAddress.ToString();
                }

                if (_config.RouteByHeaderFrom && mailItem.Message != null && mailItem.Message.From != null)
                {
                    senderAddress = mailItem.Message.From.SmtpAddress;
                    LogInfo(string.Format("Using From header (P2) for rule matching: {0}", senderAddress ?? "(null)"));
                }

                // Fallback to envelope sender
                if (string.IsNullOrEmpty(senderAddress))
                {
                    senderAddress = envelopeSender;
                }

                // Find matching rule considering actual recipients
                // We need to check recipients because rules may have recipient conditions
                RoutingRule matchingRule = null;
                if (!string.IsNullOrEmpty(senderAddress) && _config.RoutingRules.Count > 0)
                {
                    // Find first external recipient that matches a rule
                    foreach (var recipient in mailItem.Recipients)
                    {
                        string recipientAddress = recipient.Address.ToString();

                        // Skip local recipients when looking for matching rule
                        if (_config.BypassLocalRecipients && IsLocalRecipient(recipientAddress))
                        {
                            continue;
                        }

                        var rule = FindMatchingRule(senderAddress, recipientAddress);
                        if (rule != null)
                        {
                            matchingRule = rule;
                            LogInfo(string.Format("Found matching rule '{0}' for sender={1}, recipient={2}",
                                rule.Name ?? "(unnamed)", senderAddress, recipientAddress));
                            break;
                        }
                    }

                    // If no recipient-specific rule found, try sender-only rules (rules without recipient conditions)
                    if (matchingRule == null)
                    {
                        matchingRule = FindMatchingRule(senderAddress);
                    }
                }

                // Apply Send-As-Alias from rule (takes precedence over generic alias detection)
                if (matchingRule != null && !string.IsNullOrEmpty(matchingRule.SendAsAlias))
                {
                    ApplyRuleSendAsAlias(mailItem, senderAddress, matchingRule.SendAsAlias);
                }
                // Fallback to generic Send-As-Alias detection
                else if (_config.EnableSendAsAlias)
                {
                    ApplySendAsAlias(mailItem);
                }

                // Apply Sender-Based Routing
                if (_config.EnableSenderBasedRouting)
                {
                    ApplySenderBasedRouting(source, mailItem, senderAddress);
                }
            }
            catch (Exception ex)
            {
                // Log error but do not block message delivery
                LogError(string.Format("Error processing message: {0}\n{1}", ex.Message, ex.StackTrace));
            }
        }

        /// <summary>
        /// Applies Send-As-Alias based on rule configuration.
        /// Validates proxy addresses if configured.
        /// </summary>
        private void ApplyRuleSendAsAlias(MailItem mailItem, string senderAddress, string sendAsAlias)
        {
            if (mailItem == null || mailItem.Message == null || string.IsNullOrEmpty(senderAddress))
                return;

            string aliasAddress = null;
            string aliasDomain = null;

            // If sendAsAlias starts with @, it's a domain - construct alias from sender's local part + domain
            if (sendAsAlias.StartsWith("@"))
            {
                aliasDomain = sendAsAlias.Substring(1).ToLowerInvariant();
                int atIndex = senderAddress.IndexOf('@');
                if (atIndex > 0)
                {
                    string localPart = senderAddress.Substring(0, atIndex);
                    aliasAddress = localPart + sendAsAlias;
                }
            }
            else
            {
                // Use the full alias address as specified
                aliasAddress = sendAsAlias;
                int atIndex = sendAsAlias.IndexOf('@');
                if (atIndex > 0)
                {
                    aliasDomain = sendAsAlias.Substring(atIndex + 1).ToLowerInvariant();
                }
            }

            if (string.IsNullOrEmpty(aliasAddress))
            {
                LogWarning(string.Format("Send-As-Alias: Could not construct alias from '{0}' and '{1}'",
                    senderAddress, sendAsAlias));
                return;
            }

            // Validate proxy addresses if configured
            if (_config.ValidateProxyAddresses && !string.IsNullOrEmpty(aliasDomain))
            {
                // Check if the current From header (P2) is already in the alias domain
                // This indicates the user selected a valid alias from their proxy addresses
                string currentFrom = null;
                if (mailItem.Message.From != null)
                {
                    currentFrom = mailItem.Message.From.SmtpAddress;
                }

                bool hasAliasInDomain = false;

                if (!string.IsNullOrEmpty(currentFrom))
                {
                    int atIdx = currentFrom.LastIndexOf('@');
                    if (atIdx > 0)
                    {
                        string currentDomain = currentFrom.Substring(atIdx + 1).ToLowerInvariant();
                        hasAliasInDomain = string.Equals(currentDomain, aliasDomain, StringComparison.OrdinalIgnoreCase);

                        if (hasAliasInDomain)
                        {
                            // User already has From header set to alias domain - use that exact address
                            aliasAddress = currentFrom;
                            LogInfo(string.Format("Send-As-Alias: User has alias in domain '{0}', using existing From: {1}",
                                aliasDomain, currentFrom));
                        }
                    }
                }

                if (!hasAliasInDomain)
                {
                    if (_config.BlockIfNoAlias)
                    {
                        LogWarning(string.Format("Send-As-Alias: Sender '{0}' does not have alias in domain '{1}'. Blocking external routing.",
                            senderAddress, aliasDomain));
                        // Don't apply alias - let the message continue without modification
                        // The routing will still not be applied if this is checked in the routing logic
                        return;
                    }
                    else
                    {
                        LogWarning(string.Format("Send-As-Alias: Sender '{0}' does not have alias in domain '{1}'. Constructing alias anyway.",
                            senderAddress, aliasDomain));
                    }
                }
            }

            LogInfo(string.Format("Send-As-Alias: Rule specifies alias '{0}' for sender '{1}'",
                aliasAddress, senderAddress));

            try
            {
                // Preserve display name if available
                string displayName = null;
                if (mailItem.Message.From != null)
                {
                    displayName = mailItem.Message.From.DisplayName;
                }

                // Set From header (P2)
                mailItem.Message.From = new EmailRecipient(displayName, aliasAddress);
                LogInfo(string.Format("Send-As-Alias: Set From header to '{0}' (display: {1})",
                    aliasAddress, displayName ?? "(none)"));

                // Set envelope sender / Return-Path (P1)
                try
                {
                    var newFromAddress = new RoutingAddress(aliasAddress);
                    mailItem.FromAddress = newFromAddress;
                    LogInfo(string.Format("Send-As-Alias: Set Return-Path/MAIL FROM to '{0}'", aliasAddress));
                }
                catch (Exception exEnvelope)
                {
                    LogWarning(string.Format("Send-As-Alias: Could not set Return-Path: {0}", exEnvelope.Message));
                }
            }
            catch (Exception ex)
            {
                LogError(string.Format("Send-As-Alias: Failed to set From: {0}", ex.Message));
            }
        }

        /// <summary>
        /// Preserves the sender alias address in the From header.
        /// Also checks Sender header and X-MS headers for original alias.
        /// </summary>
        private void ApplySendAsAlias(MailItem mailItem)
        {
            if (mailItem == null || mailItem.Message == null)
            {
                LogInfo("Send-As-Alias: MailItem or Message is null, skipping");
                return;
            }

            // Get envelope sender (P1) - this is the primary SMTP address
            string envelopeSender = null;
            if (mailItem.FromAddress != null)
            {
                envelopeSender = mailItem.FromAddress.ToString();
            }

            // Get header From (P2) - may already be rewritten by Exchange
            string headerFrom = null;
            string displayName = null;

            if (mailItem.Message.From != null)
            {
                headerFrom = mailItem.Message.From.SmtpAddress;
                displayName = mailItem.Message.From.DisplayName;
            }

            // Also check Sender header (might contain original)
            string senderHeader = null;
            if (mailItem.Message.Sender != null)
            {
                senderHeader = mailItem.Message.Sender.SmtpAddress;
            }

            // Check raw MIME headers for original From
            string rawFromHeader = null;
            try
            {
                var mimeFrom = mailItem.Message.MimeDocument.RootPart.Headers.FindFirst(HeaderId.From);
                if (mimeFrom != null)
                {
                    rawFromHeader = mimeFrom.Value;
                }
            }
            catch { }

            // Check for X-MS-Exchange-Organization-AuthAs header
            string authAs = null;
            try
            {
                var authHeader = mailItem.Message.MimeDocument.RootPart.Headers.FindFirst("X-MS-Exchange-Organization-AuthAs");
                if (authHeader != null)
                {
                    authAs = authHeader.Value;
                }
            }
            catch { }

            LogInfo(string.Format("Send-As-Alias: P1={0}, P2={1}, Sender={2}, RawFrom={3}, AuthAs={4}",
                envelopeSender ?? "(null)",
                headerFrom ?? "(null)",
                senderHeader ?? "(null)",
                rawFromHeader ?? "(null)",
                authAs ?? "(null)"));

            if (string.IsNullOrEmpty(envelopeSender))
            {
                LogInfo("Send-As-Alias: No envelope sender, skipping");
                return;
            }

            // Determine if an alias was used
            // Priority: Sender header > Header From > Raw MIME From
            string aliasAddress = null;

            // Check if Sender header has a different address (indicates Send-As)
            if (!string.IsNullOrEmpty(senderHeader) &&
                !string.Equals(senderHeader, envelopeSender, StringComparison.OrdinalIgnoreCase))
            {
                aliasAddress = senderHeader;
                LogInfo(string.Format("Send-As-Alias: Found alias in Sender header: {0}", aliasAddress));
            }
            // Check if P2 differs from P1
            else if (!string.IsNullOrEmpty(headerFrom) &&
                     !string.Equals(headerFrom, envelopeSender, StringComparison.OrdinalIgnoreCase))
            {
                aliasAddress = headerFrom;
                LogInfo(string.Format("Send-As-Alias: Found alias in From header: {0}", aliasAddress));
            }

            if (!string.IsNullOrEmpty(aliasAddress))
            {
                // Set the From header to the alias
                try
                {
                    mailItem.Message.From = new EmailRecipient(displayName, aliasAddress);
                    LogInfo(string.Format("Send-As-Alias: Set From to alias {0}", aliasAddress));
                }
                catch (Exception ex)
                {
                    LogError(string.Format("Send-As-Alias: Failed to set From: {0}", ex.Message));
                }
            }
            else
            {
                LogInfo("Send-As-Alias: No alias detected (all addresses match P1)");
            }
        }

        /// <summary>
        /// Routes messages through specific connectors based on sender domain/address rules.
        /// Uses connector address spaces - direct smart host IPs are not supported.
        /// Now supports per-recipient routing based on recipient conditions in rules.
        /// </summary>
        private void ApplySenderBasedRouting(ResolvedMessageEventSource source, MailItem mailItem, string senderAddress)
        {
            if (string.IsNullOrEmpty(senderAddress))
            {
                LogInfo("Sender-Based Routing: No sender address found, skipping");
                return;
            }

            // Apply routing override to recipients (skip local if configured)
            int routedCount = 0;
            int skippedCount = 0;
            int noRuleCount = 0;

            foreach (var recipient in mailItem.Recipients)
            {
                try
                {
                    string recipientAddress = recipient.Address.ToString();

                    // Check if recipient is local and should be bypassed
                    if (_config.BypassLocalRecipients && IsLocalRecipient(recipientAddress))
                    {
                        LogInfo(string.Format("Sender-Based Routing: Skipping local recipient {0}", recipientAddress));
                        skippedCount++;
                        continue;
                    }

                    // Find matching rule for this specific recipient
                    var rule = FindMatchingRule(senderAddress, recipientAddress);

                    if (rule == null)
                    {
                        LogInfo(string.Format("Sender-Based Routing: No rule matches sender={0}, recipient={1}",
                            senderAddress, recipientAddress));
                        noRuleCount++;
                        continue;
                    }

                    // Only address spaces are supported (connector-based routing)
                    if (string.IsNullOrEmpty(rule.ConnectorAddressSpace))
                    {
                        LogWarning(string.Format("Sender-Based Routing: Rule '{0}' matched but no addressSpace configured",
                            rule.Name ?? "(unnamed)"));
                        noRuleCount++;
                        continue;
                    }

                    string addressSpace = rule.ConnectorAddressSpace;

                    var routingDomain = new RoutingDomain(addressSpace);
                    var routingOverride = new RoutingOverride(routingDomain, DeliveryQueueDomain.UseOverrideDomain);

                    source.SetRoutingOverride(recipient, routingOverride);
                    routedCount++;

                    LogInfo(string.Format("Sender-Based Routing: Rule='{0}', Recipient={1} -> {2}",
                        rule.Name ?? "(unnamed)", recipientAddress, addressSpace));
                }
                catch (Exception ex)
                {
                    LogError(string.Format("Failed to set routing override for {0}: {1}",
                        recipient.Address.ToString(), ex.Message));
                }
            }

            LogInfo(string.Format("Sender-Based Routing: Routed={0}, Skipped(local)={1}, NoRule={2}",
                routedCount, skippedCount, noRuleCount));
        }

        /// <summary>
        /// Checks if a recipient is local (matches configured local domains).
        /// </summary>
        private bool IsLocalRecipient(string recipientAddress)
        {
            if (string.IsNullOrEmpty(recipientAddress))
                return false;

            int atIndex = recipientAddress.LastIndexOf('@');
            if (atIndex < 0)
                return false;

            string recipientDomain = recipientAddress.Substring(atIndex + 1).ToLowerInvariant();

            // Check against configured local domains
            foreach (var localDomain in _config.LocalDomains)
            {
                if (string.Equals(recipientDomain, localDomain, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Finds matching rule for sender address only (for alias detection).
        /// </summary>
        private RoutingRule FindMatchingRule(string senderAddress)
        {
            return FindMatchingRule(senderAddress, null);
        }

        /// <summary>
        /// Finds matching rule for sender and optionally recipient.
        /// Rules are evaluated in order; first match wins.
        /// Supports wildcards (* and ?) in sender/recipient patterns.
        /// </summary>
        private RoutingRule FindMatchingRule(string senderAddress, string recipientAddress)
        {
            if (string.IsNullOrEmpty(senderAddress))
                return null;

            foreach (var rule in _config.RoutingRules)
            {
                // Skip disabled rules
                if (!rule.Enabled)
                    continue;

                // Check sender match (with wildcard support)
                if (!rule.MatchesSender(senderAddress))
                    continue;

                // Check recipient conditions (with wildcard support)
                if (rule.MatchesRecipient(recipientAddress))
                {
                    return rule;
                }
            }

            return null;
        }

        private void LogInfo(string message)
        {
            // Write to file log
            if (_fileLogger != null)
            {
                _fileLogger.LogInfo(message);
            }

            // Write to Event Log
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

        private void LogWarning(string message)
        {
            // Write to file log
            if (_fileLogger != null)
            {
                _fileLogger.LogWarning(message);
            }

            // Write to Event Log
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

        private void LogError(string message)
        {
            // Write to file log
            if (_fileLogger != null)
            {
                _fileLogger.LogError(message);
            }

            // Write to Event Log
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

        private void LogDebug(string message)
        {
            // Write to file log only (debug level not written to Event Log)
            if (_fileLogger != null)
            {
                _fileLogger.LogDebug(message);
            }
        }

        private void LogVerbose(string message)
        {
            // Write to file log only (verbose level not written to Event Log)
            if (_fileLogger != null)
            {
                _fileLogger.LogVerbose(message);
            }
        }
    }
}
