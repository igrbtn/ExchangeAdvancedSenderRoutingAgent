using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Routing;

namespace AdvancedSenderRouting
{
    /// <summary>
    /// Factory class for creating AdvancedSenderRoutingAgent instances.
    /// This is the entry point registered with Exchange Transport Service.
    /// </summary>
    public sealed class AdvancedSenderRoutingAgentFactory : RoutingAgentFactory
    {
        private readonly RoutingConfiguration _configuration;

        public AdvancedSenderRoutingAgentFactory()
        {
            _configuration = RoutingConfiguration.Load();
        }

        public override RoutingAgent CreateAgent(SmtpServer server)
        {
            return new AdvancedSenderRoutingAgent(_configuration);
        }
    }
}
