package eu.ngpaas.nat.core;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.ngpaas.pmlib.ForwardingObjectiveList;
import eu.ngpaas.pmlib.PolicyAction;
import eu.ngpaas.pmlib.PolicyCondition;
import eu.ngpaas.pmlib.PolicyRule;
import eu.ngpaas.pmlib.PolicyRules;
import eu.ngpaas.pmlib.PolicyService;
import eu.ngpaas.pmlib.SimpleResponse;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.onlab.osgi.DefaultServiceDirectory;
import org.onlab.packet.ARP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class NATManager implements PolicyService {
    private static final int FLOW_PRIORITY = 100;
    private static ApplicationId applicationId;
    private static boolean isActive = false;
    /**
     * The IPs NAT table:
     * Key: original IP
     * value: natted IP
     */
    private static Map<IpPrefix, IpPrefix> real2natted_ip = new HashMap<>();
    /**
     * The IP-to-MAC table:
     * Key: natted IP
     * value: original MAC
     */
    private static Map<IpPrefix, MacAddress> natted_ip_to_mac = new HashMap<>();
    /**
     * The IP-to-MAC table:
     * Key: natted IP
     * value: original MAC
     */
    private static Map<MacAddress, MacAddress> real_mac_to_natted_mac = new HashMap<>();
    /**
     * The IP-to-MAC table:
     * Key: natted IP
     * value: original MAC
     */
    private static Map<MacAddress, MacAddress> natted_mac_to_real_mac = new HashMap<>();
    private final Logger log = LoggerFactory.getLogger(getClass());
    private WebTarget RESTtarget = ClientBuilder.newClient(new ClientConfig())
                                                .register(HttpAuthenticationFeature.basic("onos", "rocks"))
                                                .target(UriBuilder.fromUri("http://localhost:8181/onos/policymanager")
                                                                  .build());
    private FlowObjectiveService flowObjectiveService = DefaultServiceDirectory.getService(FlowObjectiveService.class);
    private CoreService coreService = DefaultServiceDirectory.getService(CoreService.class);
    private HostService hostService = DefaultServiceDirectory.getService(HostService.class);

    private ReactivePacketProcessor processor = new ReactivePacketProcessor();

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private TopologyService topologyService;

    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    // Indicates whether this is a control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    // Selects a path from the given set that does not lead back to the specified port if possible.
    private Path pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        for (Path path : paths) {
            if (!path.src().port().equals(notToPort)) {
                return path;
            }
        }
        return null;
    }

    /**
     * Processes the ARP Payload and initiates a reply to the client.
     *
     * @param packetContext context of the incoming message
     * @param ethPkt        the ethernet payload
     */
    private void processArpRequest(PacketContext packetContext, Ethernet ethPkt, MacAddress replyMac) {

        ARP arpPacket = (ARP) ethPkt.getPayload();

        ARP arpReply = (ARP) arpPacket.clone();
        arpReply.setOpCode(ARP.OP_REPLY);

        arpReply.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());
        arpReply.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
        arpReply.setSenderProtocolAddress(arpPacket.getTargetProtocolAddress());
        arpReply.setSenderHardwareAddress(replyMac.toBytes());

        // Ethernet Frame.
        Ethernet ethReply = new Ethernet();
        ethReply.setSourceMACAddress(replyMac);
        ethReply.setDestinationMACAddress(ethPkt.getSourceMAC());
        ethReply.setEtherType(Ethernet.TYPE_ARP);
        ethReply.setVlanID(ethPkt.getVlanID());

        ethReply.setPayload(arpReply);
        sendReply(packetContext, ethReply);
    }

    /**
     * Sends the Ethernet reply frame via the Packet Service.
     *
     * @param pktContext the context of the incoming frame
     * @param arpReply   the Ethernet reply frame
     */
    private void sendReply(PacketContext pktContext, Ethernet arpReply) {
        if (arpReply != null) {
            TrafficTreatment.Builder arpTreatment = DefaultTrafficTreatment.builder();
            ConnectPoint sourcePoint = pktContext.inPacket().receivedFrom();
            arpTreatment.setOutput(sourcePoint.port());
            pktContext.block();
            packetService.emit(new DefaultOutboundPacket(sourcePoint.deviceId(),
                                                         arpTreatment.build(), ByteBuffer.wrap(arpReply.serialize())));
        }
    }

    private String randomMACAddress() {
        Random rand = new Random();
        byte[] macAddr = new byte[6];
        rand.nextBytes(macAddr);

        macAddr[0] = (byte) (macAddr[0] & (byte) 254); //zeroing last 2 bytes to make it unicast and locally
        // administrated

        StringBuilder sb = new StringBuilder(18);
        for (byte b : macAddr) {

            if (sb.length() > 0) {
                sb.append(":");
            }

            sb.append(String.format("%02x", b));
        }

        return sb.toString();

        //TODO: Calculate MAC again if it is already used by a host in the network (obtained from hostService)
    }

    @Activate
    protected void activate() {
        log.info("NAT Policy started");
        applicationId = coreService.registerApplication("NATpolicy");
        packetService.addProcessor(processor, PacketProcessor.director(1));
        Response response = RESTtarget.path("policytype/register/nat")
                                      .request(MediaType.APPLICATION_JSON)
                                      .put(Entity.text(""));

        if (response.getStatus() != Response.Status.OK.getStatusCode()) {
            log.info("Policy Framework not found.");
            throw new RuntimeException();
        } else {
            log.info("NAT policy type successfully registered.");
        }
    }

    @Deactivate
    protected void deactivate() {
        log.info("NAT Policy stopped");
        packetService.removeProcessor(processor);
        processor = null;
        real2natted_ip.clear();
        natted_mac_to_real_mac.clear();
        real_mac_to_natted_mac.clear();
        natted_ip_to_mac.clear();
        Response response = RESTtarget.path("policytype/deregister/nat").request(MediaType.APPLICATION_JSON).delete();
        String prsJSON = response.readEntity(String.class);
        log.info(prsJSON);
        PolicyRules prs = parsePolicyRules(prsJSON);
        for (PolicyRule pr : prs.getPolicyRules()) {
            remove(pr);
        }
    }

    public PolicyRules parsePolicyRules(String json) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        PolicyRules policyRules = null;
        try {
            policyRules = mapper.readValue(json, PolicyRules.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return policyRules;
    }

    @Override
    public SimpleResponse formalValidation(PolicyRule pr) {
        SimpleResponse restResponse;
        // check all conditions of each new policy

        for (CopyOnWriteArrayList<PolicyCondition> clause : pr.getPolicyConditions()) {
            if (clause.size() > 1) {
                restResponse = new SimpleResponse("Formal error: Only one condition is supported.", false);
                return restResponse;
            } else if (clause.size() == 0) {
                restResponse = new SimpleResponse("Formal error: No policy conditions.", false);
                return restResponse;
            } else {
                PolicyCondition pc = clause.get(0);
                if (!(pc.getPolicyVariable().equalsIgnoreCase("host_ip"))) {
                    restResponse = new SimpleResponse(
                        "Formal error: Parameter " + pc.getPolicyVariable() + " invalid. Valid parameter: host_ip.",
                        false);
                    return restResponse;
                }
            }
        }
        if (pr.getPolicyActions().size() > 1) {
            restResponse = new SimpleResponse("Formal error: Only one action is supported.", false);
            return restResponse;
        } else if (pr.getPolicyActions().size() == 0) {
            restResponse = new SimpleResponse("Formal error: No policy actions.", false);
            return restResponse;
        } else {

            PolicyAction pa = pr.getPolicyActions().get(0);
            if (!(pa.getPolicyVariable().equalsIgnoreCase("natted_ip"))) {
                restResponse = new SimpleResponse(
                    "Formal error: Parameter " + pa.getPolicyVariable() + " invalid. Valid parameter: natted_ip.",
                    false);
                return restResponse;
            }
        }
        restResponse = new SimpleResponse("Formal validated.", true);
        return restResponse;
    }

    @Override
    public SimpleResponse contextValidation(PolicyRule pr) {

        for (CopyOnWriteArrayList<PolicyCondition> clause : pr.getPolicyConditions()) {
            if (!conditionsContextValidator(clause) ||
                !actionsContextValidation(clause)) {
                return new SimpleResponse("Policy failed at context validation", false);
            }
        }
        return new SimpleResponse("Policy context validated", true);
    }

    //Check that all the hosts exist
    private Boolean conditionsContextValidator(CopyOnWriteArrayList<PolicyCondition> pcs) {
        for (PolicyCondition pc : pcs) {
            HostService hostService = DefaultServiceDirectory.getService(HostService.class);
            if (hostService.getHostsByIp(IpAddress.valueOf(pc.getPolicyValue())).isEmpty()) {
                return false;
            }
        }
        return true;
    }

    //Check that natted IP is not being used
    private Boolean actionsContextValidation(CopyOnWriteArrayList<PolicyCondition> pcs) {
        return true;
    }

    @Override
    public void enforce(PolicyRule pr) {
        PolicyAction pa = pr.getPolicyActions().get(0);

        //Define the applicationId. Used later to identify the rules pushed by the policymanager.
        //applicationId = coreService.getAppId("NATpolicy");

        isActive = true;

        // Go through the conditions and build the corresponding map.
        for (CopyOnWriteArrayList<PolicyCondition> clause : pr.getPolicyConditions()) {
            for (PolicyCondition pc : clause) {
                if (!hostService.getHostsByIp(IpAddress.valueOf(pc.getPolicyValue())).isEmpty()) {
                    //log.info("Host found.");

                    real2natted_ip.put(IpPrefix.valueOf(IpAddress.valueOf(pc.getPolicyValue()), 32),
                                       IpPrefix.valueOf(IpAddress.valueOf(pa.getPolicyValue()), 32));

                    log.info("NAT rule enforced: HashMap updated");
                    log.info("Real IP: " + IpPrefix.valueOf(IpAddress.valueOf(pc.getPolicyValue()), 32).toString());
                    log.info("Natted IP: " + IpPrefix.valueOf(IpAddress.valueOf(pa.getPolicyValue()), 32).toString());

                }
            }

        }
    }

    @Override
    public void remove(PolicyRule pr) {
        PolicyAction pa = pr.getPolicyActions().get(0);

        if (real2natted_ip.isEmpty()) {
            isActive = false;
        }

        // Go through the conditions and delete the corresponding maps
        for (CopyOnWriteArrayList<PolicyCondition> clause : pr.getPolicyConditions()) {
            for (PolicyCondition pc : clause) {

                IpPrefix realIp = IpPrefix.valueOf(IpAddress.valueOf(pc.getPolicyValue()), 32);
                IpPrefix nattedIp = IpPrefix.valueOf(IpAddress.valueOf(pa.getPolicyValue()), 32);

                real2natted_ip.remove(realIp);

                natted_mac_to_real_mac.remove(real_mac_to_natted_mac.get(natted_ip_to_mac.get(nattedIp)));
                real_mac_to_natted_mac.remove(natted_ip_to_mac.get(nattedIp));
                natted_ip_to_mac.remove(nattedIp);

                log.info("NAT rule deleted: HashMaps updated");
            }
        }
    }

    @Override
    public ForwardingObjectiveList getFlowRules(PolicyRule policyRule) {
        IpPrefix net1 = null, net2 = null;

        for (CopyOnWriteArrayList<PolicyCondition> clause : policyRule.getPolicyConditions()) {
            for (PolicyCondition pc : clause) {
                if (pc.getPolicyVariable().equalsIgnoreCase("net1")) {
                    net1 = IpPrefix.valueOf(pc.getPolicyValue());
                } else {
                    net2 = IpPrefix.valueOf(pc.getPolicyValue());
                }
            }
            // Create the traffic selector.
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            selector.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPSrc(net1)
                    .matchIPDst(net2);

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
            treatment.setIpDst(net1.address());

            /*ForwardingObjective.Builder fwdObj = DefaultForwardingObjective.builder()
                    .makePermanent()
                    .withPriority(FLOW_PRIORITY + policyRule.getPriority())
                    .withSelector(selector6.build())
                    .withTreatment(treatment6.build())
                    .fromApp(applicationId)
                    .withFlag(ForwardingObjective.Flag.VERSATILE);*/
        }
        return null;
    }

    private class ReactivePacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {

            if (isActive) {

                /*if (context.isHandled()) {
                    return;
                }*/

                InboundPacket pkt = context.inPacket();

                Ethernet ethPkt = pkt.parsed();
                if (ethPkt == null) {
                    return;
                }

                // Bail if this is deemed to be a control packet.
                if (isControlPacket(ethPkt)) {
                    return;
                }

                // ARP packet
                if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                    ARP arpPacket = (ARP) ethPkt.getPayload();

                    // Process only ARP requests for natted IPs
                    if ((arpPacket.getOpCode() == ARP.OP_REQUEST)) {
                        for (IpPrefix ipp : real2natted_ip.values()) {
                            if (Ip4Address.valueOf(arpPacket.getTargetProtocolAddress()).equals(ipp.address())) {
                                log.info(" -- ARP request: who has {}",
                                         Ip4Address.valueOf(arpPacket.getTargetProtocolAddress()));
                                log.info("Returned MAC: " + real_mac_to_natted_mac.get(natted_ip_to_mac.get(ipp))
                                                                                  .toString());
                                processArpRequest(context, ethPkt,
                                                  real_mac_to_natted_mac.get(natted_ip_to_mac.get(ipp)));
                                context.block();
                                break;
                            }
                        }
                    }
                }
                // IP packet
                else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {

                    IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();

                    // Define source and destination IPs
                    IpPrefix srcIp = Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(), 32);
                    IpPrefix dstIp = Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(), 32);

                    // Find source and destination hosts
                    Host src_host;
                    Host dst_host;
                    if (natted_mac_to_real_mac.keySet().contains(ethPkt.getSourceMAC())) {
                        src_host = hostService
                            .getHost(HostId.hostId(natted_mac_to_real_mac.get(ethPkt.getSourceMAC())));
                    } else {
                        src_host = hostService.getHost(HostId.hostId(ethPkt.getSourceMAC()));
                    }

                    if (natted_mac_to_real_mac.keySet().contains(ethPkt.getDestinationMAC())) {
                        dst_host = hostService
                            .getHost(HostId.hostId(natted_mac_to_real_mac.get(ethPkt.getDestinationMAC())));
                    } else {
                        dst_host = hostService.getHost(HostId.hostId(ethPkt.getDestinationMAC()));
                    }

                    // If the destination host is attached to the same device as the source host
                    if (src_host.location().deviceId().equals(dst_host.location().deviceId())) {
                        // Simply return and let default forwarding take the request
                        return;
                    }
                    // If the source and destination hosts are in different devices and the destination host is
                    // natted
                    if (real2natted_ip.keySet().contains(dstIp) || real2natted_ip.values().contains(dstIp)) {

                        log.info("Natted destination. Drop packet.");

                        // Create the traffic selector.
                        TrafficSelector.Builder dropSelector = DefaultTrafficSelector.builder();
                        dropSelector.matchEthType(Ethernet.TYPE_IPV4)
                                    .matchIPSrc(srcIp)
                                    .matchIPDst(dstIp);

                        // Create the traffic treatment object.
                        TrafficTreatment.Builder dropTreatment = DefaultTrafficTreatment.builder();
                        dropTreatment.drop();

                        // Create and push the forwarding objective.
                        ForwardingObjective.Builder fwdObj = DefaultForwardingObjective.builder()
                                                                                       .makeTemporary(20)
                                                                                       .withPriority(FLOW_PRIORITY)
                                                                                       .withSelector(
                                                                                           dropSelector.build())
                                                                                       .withTreatment(
                                                                                           dropTreatment.build())
                                                                                       .fromApp(applicationId)
                                                                                       .withFlag(
                                                                                           ForwardingObjective.Flag
                                                                                               .VERSATILE);

                        flowObjectiveService.forward(pkt.receivedFrom().deviceId(), fwdObj.add());

                        packetOut(context, PortNumber.TABLE);

                        context.block();
                        return;
                    }

                    // If the source and destination hosts are in different devices, the destination host is not natted
                    // the source host is natted and the pktIn is received from the device of the natted host
                    if (real2natted_ip.keySet().contains(srcIp) && pkt.receivedFrom().deviceId()
                                                                      .equals(src_host.location().deviceId())) {

                        // If the a random MAC is not yet associated to the source host
                        if (!real_mac_to_natted_mac.keySet().contains(ethPkt.getSourceMAC())) {

                            // Calculate randomMAC (natted MAC)
                            MacAddress randomMAC = MacAddress.valueOf(randomMACAddress());

                            // Update MAC tables
                            real_mac_to_natted_mac.put(ethPkt.getSourceMAC(), randomMAC);
                            natted_mac_to_real_mac.put(randomMAC, ethPkt.getSourceMAC());

                            // Update natted IP to MAC table
                            natted_ip_to_mac.put(real2natted_ip.get(srcIp), ethPkt.getSourceMAC());
                        }

                        // Get a set of paths that lead from here to the destination edge switch.
                        Set<Path> paths =
                            topologyService.getPaths(topologyService.currentTopology(),
                                                     pkt.receivedFrom().deviceId(),
                                                     dst_host.location().deviceId());

                        // If there are no paths just return.
                        if (paths.isEmpty()) {
                            return;
                        }

                        // Otherwise, pick a path that does not lead back to where we
                        // came from. If not return.
                        Path path = pickForwardPathIfPossible(paths, pkt.receivedFrom().port());
                        if (path == null) {
                            log.warn("Don't know where to go from here {} for {} -> {}",
                                     pkt.receivedFrom(), ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
                            return;
                        }

                        // (1) NAT the IP/MAC and forward request packets to the next device.

                        // Create the traffic selector.
                        TrafficSelector.Builder selector1 = DefaultTrafficSelector.builder();
                        selector1.matchEthType(Ethernet.TYPE_IPV4)
                                 .matchIPSrc(srcIp)
                                 .matchIPDst(dstIp);

                        // Create the traffic treatment object
                        TrafficTreatment.Builder treatment1 = DefaultTrafficTreatment.builder();

                        // NAT source IP
                        treatment1.setIpSrc(real2natted_ip.get(srcIp).address());
                        log.info("Natted IP from " + srcIp.address().toString() + " to " + real2natted_ip.get(srcIp)
                                                                                                         .address()
                                                                                                         .toString());

                        // NAT source MAC
                        treatment1.setEthSrc(real_mac_to_natted_mac.get(ethPkt.getSourceMAC()));

                        // Forward packet to the next device of the path
                        treatment1.setOutput(path.src().port());

                        // Create the forwarding objective
                        ForwardingObjective.Builder fwdObj1 = DefaultForwardingObjective.builder()
                                                                                        .makeTemporary(20)
                                                                                        .withPriority(FLOW_PRIORITY)
                                                                                        .withSelector(selector1.build())
                                                                                        .withTreatment(
                                                                                            treatment1.build())
                                                                                        .fromApp(applicationId)
                                                                                        .withFlag(
                                                                                            ForwardingObjective.Flag
                                                                                                .VERSATILE);

                        // Push the forwarding objective
                        flowObjectiveService.forward(pkt.receivedFrom().deviceId(), fwdObj1.add());


                        // (2) Undo the IP/MAC NAT and forward reply packets back to the host

                        // Create the traffic selector
                        TrafficSelector.Builder selector2 = DefaultTrafficSelector.builder();
                        selector2.matchEthType(Ethernet.TYPE_IPV4)
                                 .matchEthSrc(ethPkt.getDestinationMAC())
                                 .matchEthDst(real_mac_to_natted_mac.get(ethPkt.getSourceMAC()))
                                 .matchIPDst(IpPrefix.valueOf(real2natted_ip.get(srcIp).address(), 32));

                        // Create the traffic treatment: put back the original IP of the host as destination IP
                        // and forward the packet to the host.
                        TrafficTreatment.Builder treatment2 = DefaultTrafficTreatment.builder();
                        treatment2.setIpDst(srcIp.address())
                                  .setEthDst(ethPkt.getSourceMAC())
                                  .setOutput(src_host.location().port());

                        // Create the forwarding objective
                        ForwardingObjective.Builder fwdObj2 = DefaultForwardingObjective.builder()
                                                                                        .makeTemporary(20)
                                                                                        .withPriority(FLOW_PRIORITY)
                                                                                        .withSelector(selector2.build())
                                                                                        .withTreatment(
                                                                                            treatment2.build())
                                                                                        .fromApp(applicationId)
                                                                                        .withFlag(
                                                                                            ForwardingObjective.Flag
                                                                                                .VERSATILE);

                        // Push the forwarding objective
                        flowObjectiveService.forward(pkt.receivedFrom().deviceId(), fwdObj2.add());

                        packetOut(context, PortNumber.TABLE);

                        context.block();

                        return;
                    }

                    // If the source IP is a natted IP (i.e., this traffic has already been natted)
                    if (real2natted_ip.values().contains(srcIp)) {

                        // Are we on an edge switch that our destination is on?
                        if (pkt.receivedFrom().deviceId().equals(dst_host.location().deviceId())) {
                            if (!context.inPacket().receivedFrom().port().equals(dst_host.location().deviceId())) {

                                // (1) Forward request packets to the destination host

                                // Create the traffic selector.
                                TrafficSelector.Builder selector3 = DefaultTrafficSelector.builder();
                                selector3.matchEthType(Ethernet.TYPE_IPV4)
                                         .matchIPSrc(srcIp)
                                         .matchIPDst(dstIp);

                                // Create the traffic treatment
                                TrafficTreatment.Builder treatment3 = DefaultTrafficTreatment.builder();
                                treatment3.setOutput(dst_host.location().port());

                                // Create the forwarding objective
                                ForwardingObjective.Builder fwdObj3 = DefaultForwardingObjective.builder()
                                                                                                .makeTemporary(20)
                                                                                                .withPriority(
                                                                                                    FLOW_PRIORITY)
                                                                                                .withSelector(
                                                                                                    selector3.build())
                                                                                                .withTreatment(
                                                                                                    treatment3.build())
                                                                                                .fromApp(applicationId)
                                                                                                .withFlag(
                                                                                                    ForwardingObjective.Flag.VERSATILE);

                                // Push the forwarding objective
                                flowObjectiveService.forward(pkt.receivedFrom().deviceId(), fwdObj3.add());

                                // (2) Forward reply packets back to the source host.

                                // Create the traffic selector.
                                TrafficSelector.Builder selector4 = DefaultTrafficSelector.builder();
                                selector4.matchEthType(Ethernet.TYPE_IPV4)
                                         .matchIPSrc(dstIp)
                                         .matchIPDst(srcIp);

                                // Create the traffic treatment
                                TrafficTreatment.Builder treatment4 = DefaultTrafficTreatment.builder();
                                treatment4.setOutput(pkt.receivedFrom().port());

                                // Create the forwarding objective
                                ForwardingObjective.Builder fwdObj4 = DefaultForwardingObjective.builder()
                                                                                                .makeTemporary(20)
                                                                                                .withPriority(
                                                                                                    FLOW_PRIORITY)
                                                                                                .withSelector(
                                                                                                    selector4.build())
                                                                                                .withTreatment(
                                                                                                    treatment4.build())
                                                                                                .fromApp(applicationId)
                                                                                                .withFlag(
                                                                                                    ForwardingObjective.Flag.VERSATILE);

                                // Push the forwarding objective
                                flowObjectiveService.forward(pkt.receivedFrom().deviceId(), fwdObj4.add());

                                packetOut(context, PortNumber.TABLE);

                                context.block();
                            }
                            return;
                        }

                        // Otherwise, get a set of paths that lead from here to the destination edge switch.
                        Set<Path> paths =
                            topologyService.getPaths(topologyService.currentTopology(),
                                                     pkt.receivedFrom().deviceId(),
                                                     dst_host.location().deviceId());

                        // If there are no paths just return.
                        if (paths.isEmpty()) {
                            return;
                        }

                        // Otherwise, pick a path that does not lead back to where we
                        // came from. If not return.
                        Path path = pickForwardPathIfPossible(paths, pkt.receivedFrom().port());
                        if (path == null) {
                            log.warn("Don't know where to go from here {} for {} -> {}",
                                     pkt.receivedFrom(), ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
                            return;
                        }

                        // (1) Forward request packets to the next device on the path.

                        // Create the traffic selector.
                        TrafficSelector.Builder selector5 = DefaultTrafficSelector.builder();
                        selector5.matchEthType(Ethernet.TYPE_IPV4)
                                 .matchIPSrc(srcIp)
                                 .matchIPDst(dstIp);

                        // Create the traffic treatment
                        TrafficTreatment.Builder treatment5 = DefaultTrafficTreatment.builder();
                        treatment5.setOutput(path.src().port());

                        // Create the forwarding objective
                        ForwardingObjective.Builder fwdObj5 = DefaultForwardingObjective.builder()
                                                                                        .makeTemporary(20)
                                                                                        .withPriority(FLOW_PRIORITY)
                                                                                        .withSelector(selector5.build())
                                                                                        .withTreatment(
                                                                                            treatment5.build())
                                                                                        .fromApp(applicationId)
                                                                                        .withFlag(
                                                                                            ForwardingObjective.Flag
                                                                                                .VERSATILE);

                        // Push the forwarding objective
                        flowObjectiveService.forward(pkt.receivedFrom().deviceId(), fwdObj5.add());


                        // (2) Forward reply packets back to the source host.

                        // Create the traffic selector.
                        TrafficSelector.Builder selector6 = DefaultTrafficSelector.builder();
                        selector6.matchEthType(Ethernet.TYPE_IPV4)
                                 .matchIPSrc(dstIp)
                                 .matchIPDst(srcIp);

                        // Create the traffic treatment
                        TrafficTreatment.Builder treatment6 = DefaultTrafficTreatment.builder();
                        treatment6.setOutput(pkt.receivedFrom().port());

                        // Create the forwarding objective
                        ForwardingObjective.Builder fwdObj6 = DefaultForwardingObjective.builder()
                                                                                        .makeTemporary(20)
                                                                                        .withPriority(FLOW_PRIORITY)
                                                                                        .withSelector(selector6.build())
                                                                                        .withTreatment(
                                                                                            treatment6.build())
                                                                                        .fromApp(applicationId)
                                                                                        .withFlag(
                                                                                            ForwardingObjective.Flag
                                                                                                .VERSATILE);

                        // Push the forwarding objective
                        flowObjectiveService.forward(pkt.receivedFrom().deviceId(), fwdObj6.add());

                        packetOut(context, PortNumber.TABLE);

                        context.block();
                    }
                }
            }
        }
    }

}
