# Jacob McClure
# jatmcclu@ucsc.edu

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Final (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def do_final (self, packet, packet_in, port_on_switch, switch_id):
    #   Port_on_switch represents the port that the packet was received on.
    #   Switch_id represents the id of the switch that received the packet.
    msg = of.ofp_flow_mod()            # create a flow_mod to send packets
    msg.match = of.ofp_match.from_packet(packet)   # setting the match
    check_icmp = packet.find('icmp')   # is packet icmp? (variable)
    check_arp = packet.find('arp')     # is packet arp? (variable)
    check_tcp = packet.find('tcp')     # is packet tcp? (variable)
    check_ipv4 = packet.find('ipv4')   # is packet ipv4? (variable)

    # FLOOD ARP
    if check_arp is not None:          # if packet is arp...
      msg.data = packet_in
      msg.dl_type = 0x0806             # set msg to datalink type = arp
      out_action = of.ofp_action_output(port = of.OFPP_FLOOD) # flood (send to all ports)
      msg.actions.append(out_action)   # append the action
      self.connection.send(msg)        # flood if packet is arp to all ports)

    # ICMP Packet Rules:
    elif check_icmp is not None:
      print("packet is ICMP :)")
      
      #~~~~~~~~~~~~~~~~~~#
      #~~~~ SWITCH 1 ~~~~#
      #~~~~~~~~~~~~~~~~~~#
      if switch_id == 1:
        if check_ipv4.dstip == '10.0.1.10':   # if destination is Host 10
          port = 1                            # port 1 connects h10 to s1
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 1
          msg.data = packet_in
          self.connection.send(msg)           # transmit the packet out of port 1 on s1
        
        # destination is not h10
        else:
          port = 11                     # port 11 on other side of s1
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 11
          msg.data = packet_in
          self.connection.send(msg)     # transmit the packet out of port 11 on s1

      #~~~~~~~~~~~~~~~~~~#
      #~~~~ SWITCH 2 ~~~~#
      #~~~~~~~~~~~~~~~~~~#
      elif switch_id == 2:
        if check_ipv4.dstip == '10.0.2.20':   # if destination is Host 20
          port = 2                            # port 2 connects h20 to s2
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 2
          msg.data = packet_in
          self.connection.send(msg)           # transmit the packet out of port 2 on s2
        
        else:                       # destination is not h20
          port = 12                 # port 12 on other side of s2
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 12
          msg.data = packet_in 
          self.connection.send(msg) # transmit the packet out of port 12 on s2

      #~~~~~~~~~~~~~~~~~~#
      #~~~~ SWITCH 3 ~~~~#
      #~~~~~~~~~~~~~~~~~~#
      elif switch_id == 3:
        if check_ipv4.dstip == '10.0.3.30': # if destination is Host 30
          port = 3                          # port 3 connects h30 to s3
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 3
          msg.data = packet_in
          self.connection.send(msg)         # transmit the packet out of port 3 on s3
        
        else:                          # destination is not h30
          port = 13                    # port 13 on other side of s3
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 13
          msg.data = packet_in
          self.connection.send(msg)    # transmit the packet out of port 13 on s3

      #~~~~~~~~~~~~~~~~~~~~~~#
      #~ DATA CENTER SWITCH ~#
      #~~~~~~~~~~~~~~~~~~~~~~#
      elif switch_id == 5:
        if check_ipv4.dstip == '10.0.4.10': # destination is the Server
          port = 6                          # port 6 connects Server to Data Center Switch
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 6
          msg.data = packet_in
          self.connection.send(msg)         # transmit the packet out of port 6 on s5
        
        else:
          port = 14                   # port 14 on other side of s5
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 14 
          msg.data = packet_in
          self.connection.send(msg)   # transmit the packet out of port 14 on s5

      #~~~~~~~~~~~~~~~~~~~~~#
      #~~~~ CORE SWITCH ~~~~#
      #~~~~~~~~~~~~~~~~~~~~~#
      elif switch_id == 4:
        # destination is Untrusted Host
        if (check_ipv4.dstip == '156.134.2.12'):
          port = 5                          # port 5 connects Untrusted Host to Core Switch
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 5
          msg.data = packet_in
          self.connection.send(msg)         # transmit the packet out of port 5
        
        # destination is Trusted Host
        elif (check_ipv4.dstip == '104.82.214.112'):
          port = 4                          # port 4 connects Trusted Host to Core Switch
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 4
          msg.data = packet_in
          self.connection.send(msg)         # transmit the packet out of port 4 on s4

        # source IP is not the Untrusted Host
        elif (check_ipv4.srcip != '156.134.2.12'):
          print("src ip not untrusted")
          if check_ipv4.dstip == '10.0.1.10': # destination is Host 10
            print("dstip is h10")
            port = 7                          # h10 connects to Core Switch through s1 on port 7
            msg.actions.append(of.ofp_action_output(port = port)) # send out port 7
            msg.data = packet_in
            self.connection.send(msg)         # transmit the packet out of port 7 on s4

          elif check_ipv4.dstip == '10.0.2.20': # destination is Host 20
            port = 8                          # h20 connects to Core Switch through s2 on port 8
            msg.actions.append(of.ofp_action_output(port = port)) # send out port 8
            msg.data = packet_in
            self.connection.send(msg)         # transmit the packet out of port 8 on s4

          elif check_ipv4.dstip == '10.0.3.30': # destination is Host 30
            port = 9                          # h30 connects to Core Switch through s3 on port 9
            msg.actions.append(of.ofp_action_output(port = port)) # send out port 9
            msg.data = packet_in
            self.connection.send(msg)         # transmit the packet out of port 9 on s4
        
          elif check_ipv4.dstip == '10.0.4.10': # destination is the Server
            port = 10                         # port 10 connects Core Switch to Data Center Switch
            msg.actions.append(of.ofp_action_output(port = port)) # send out port 10
            msg.data = packet_in
            self.connection.send(msg)         # transmit the packet out of port 10 on s4

    # TCP Packet Rules:
    elif check_tcp is not None: # packet is TCP...
      print("packet is TCP :)")
      msg.data = packet_in      # allow switch to transmit the packet to the controller
      msg.nw_proto = 6          # nw proto for TCP is 6
      
      #~~~~~~~~~~~~~~~~~~#
      #~~~~ SWITCH 1 ~~~~#
      #~~~~~~~~~~~~~~~~~~#
      if switch_id == 1:
        # destination is Host 10
        if check_ipv4.dstip == '10.0.1.10':
          port = 1                          # port 1 connects h10 to s1
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 1
          msg.data = packet_in
          self.connection.send(msg)         # transmit the packet out of port 1 on s1
        
        # destination is not h10
        else:         
          port = 11    # port 11 on other side of s1
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 11
          msg.data = packet_in
          self.connection.send(msg) # transmit the packet out of port 11 on s1

      #~~~~~~~~~~~~~~~~~~#
      #~~~~ SWITCH 2 ~~~~#
      #~~~~~~~~~~~~~~~~~~#
      elif switch_id == 2:
        # destination is Host 20
        if check_ipv4.dstip == '10.0.2.20': 
          port = 2                  # port 2 connects h20 to s2
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 2
          msg.data = packet_in
          self.connection.send(msg) # transmit the packet out of port 2 on s2
        
        # destination is not h20
        else: 
          port = 12                 # port 12 on other side of s2
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 12
          msg.data = packet_in 
          self.connection.send(msg) # transmit the packet out of port 12 on s2

      #~~~~~~~~~~~~~~~~~~#
      #~~~~ SWITCH 3 ~~~~#
      #~~~~~~~~~~~~~~~~~~#
      elif switch_id == 3:
        # destination is Host 30
        if check_ipv4.dstip == '10.0.3.30': 
          port = 3                  # port 3 connects h30 to s3
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 3
          msg.data = packet_in
          self.connection.send(msg) # transmit the packet out of port 3 on s3
        
        # destination is not h30
        else: 
          port = 13                 # port 13 on other side of s3
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 13
          msg.data = packet_in
          self.connection.send(msg) # transmit the packet out of port 13 on s3

      #~~~~~~~~~~~~~~~~~~~~~~#
      #~ DATA CENTER SWITCH ~#
      #~~~~~~~~~~~~~~~~~~~~~~#
      elif switch_id == 5:
        # destination is the Server
        if check_ipv4.dstip == '10.0.4.10': 
          port = 6                  # port 6 connects Server to Data Center Switch
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 6
          msg.data = packet_in
          self.connection.send(msg) # transmit the packet out of port 6 on s5
        
        else:
          port = 14                 # port 14 on other side of s5
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 14 
          msg.data = packet_in
          self.connection.send(msg) # transmit the packet out of port 14 on s5

      #~~~~~~~~~~~~~~~~~~~~~#
      #~~~~ CORE SWITCH ~~~~#
      #~~~~~~~~~~~~~~~~~~~~~#
      elif switch_id == 4:
        # if source is Untrusted Host and destination is Server, drop the packet
        if ((check_ipv4.srcip == '156.134.2.12') and (check_ipv4.dstip == '10.0.4.10')):
          msg.actions = []          # send out port 5
          self.connection.send(msg) # drop the packet 
        
        # destination is Trusted Host
        elif (check_ipv4.dstip == '104.82.214.112'):
          port = 4                  # port 4 connects Trusted Host to Core Switch
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 4
          msg.data = packet_in
          self.connection.send(msg) # transmit the packet out of port 4 on s4

        # destination is Untrusted Host
        elif (check_ipv4.dstip == '156.134.2.12'):
          port = 5                  # port 5 connects Untrusted Host to Core Switch
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 5
          msg.data = packet_in
          self.connection.send(msg) # transmit the packet out of port 5 on s4

        # destination is Host 10
        elif check_ipv4.dstip == '10.0.1.10':
          print("dstip is h10")
          port = 7                  # h10 connects to Core Switch through s1 on port 7
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 7
          msg.data = packet_in
          self.connection.send(msg) # transmit the packet out of port 7 on s4

        # destination is Host 20
        elif check_ipv4.dstip == '10.0.2.20': 
          port = 8                  # h20 connects to Core Switch through s2 on port 8
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 8
          msg.data = packet_in
          self.connection.send(msg) # transmit the packet out of port 8 on s4

        # destination is Host 30
        elif check_ipv4.dstip == '10.0.3.30': 
          port = 9                  # h30 connects to Core Switch through s3 on port 9
          msg.actions.append(of.ofp_action_output(port = port)) # send out port 9
          msg.data = packet_in
          self.connection.send(msg) # transmit the packet out of port 9 on s4

        # source IP is not the Untrusted Host
        elif (check_ipv4.srcip != '156.134.2.12'):
          print("src ip not untrusted")
          # destination is the Server
          if check_ipv4.dstip == '10.0.4.10': 
            port = 10                 # port 10 connects Core Switch to Data Center Switch
            msg.actions.append(of.ofp_action_output(port = port)) # send out port 10
            msg.data = packet_in
            self.connection.send(msg) # transmit the packet out of port 10 on s4

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_final(packet, packet_in, event.port, event.dpid)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Final(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
