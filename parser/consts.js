// https://en.wikipedia.org/wiki/EtherType
export const ETHER_TYPE_IP4 = "0x0800";
export const ETHER_TYPE_IP6 = "0x86dd";
export const ETHER_TYPE_ARP = "0x0806";
export const ETHER_TYPE_WOL = "0x0842";
export const ETHER_TYPE_UNKNOWN = "0x2e00";

export const UDP_PACKET_TYPE_DEFAULT = "UDP_PACKET_TYPE_DEFAULT";

export const UDP_PACKET_TYPE_DNS = "UDP_PACKET_TYPE_DNS"; // 53
export const UDP_PACKET_MULTI_CAST_DOMAIN_NAME_SYSTEM = "UDP_PACKET_MULTI_CAST_DOMAIN_NAME_SYSTEM"; // 5353
export const UDP_PACKET_SIMPLE_SEARCH_DISCOVERY_PROTOCOL = "UDP_PACKET_MULTI_CAST_DOMAIN_NAME_SYSTEM"; // 1900
export const UDP_PACKET_QUIC_PROTOCOL = "UDP_PACKET_QUIC_PROTOCOL"; // 443
export const UDP_PACKET_LOCAL_LINK_MULTICAST_NAME_RESOLUTION = "UDP_PACKET_LOCAL_LINK_MULTICAST_NAME_RESOLUTION"; // 5355
export const UDP_PACKET_NETBIOS_NAME_SERVICE = "UDP_PACKET_NETBIOS_NAME_SERVICE"; // 137

export const UDP_PACKET_DROPBOX_LAN_SYNC = "UDP_PACKET_DROPBOX_LAN_SYNC"; // 17500
export const UDP_PACKET_SPOTIFY = "UDP_PACKET_SPOTIFY"; // 4070

export const UDP_PORTS = [
    {type: UDP_PACKET_TYPE_DNS, shortName: "DNS", longName: 'DNS', port: 53},
    {type: UDP_PACKET_MULTI_CAST_DOMAIN_NAME_SYSTEM, shortName: "MDNS", longName: 'MDNS', port: 5353},
    {type: UDP_PACKET_SIMPLE_SEARCH_DISCOVERY_PROTOCOL, shortName: "SSDP", longName: 'SSDP', port: 1900},
    {type: UDP_PACKET_QUIC_PROTOCOL, shortName: "QUIC", longName: 'QUIC', port: 443},
    {type: UDP_PACKET_LOCAL_LINK_MULTICAST_NAME_RESOLUTION, shortName: "LLMNR", longName: 'LLMNR', port: 5355},
    {type: UDP_PACKET_NETBIOS_NAME_SERVICE, shortName: "NBNS", longName: 'NBNS', port: 137},
    {type: UDP_PACKET_DROPBOX_LAN_SYNC, shortName: "Dropbox", longName: 'Dropbox', port: 17500},
    {type: UDP_PACKET_SPOTIFY, shortName: "Spotify", longName: 'Spotify', port: 4070},
]

export const ETHER_TYPES = [
    {type: ETHER_TYPE_IP4, shortName: "ETHER_TYPE_IP4", longName: 'Internet Protocol v4'},
    {type: ETHER_TYPE_ARP, shortName: "ETHER_TYPE_ARP", longName: 'Address Resolution Protocol'},
    {type: ETHER_TYPE_WOL, shortName: "ETHER_TYPE_WOL", longName: 'Wake on LAN'},
    {type: ETHER_TYPE_IP6, shortName: "ETHER_TYPE_IP6", longName: 'Internet Protocol v6'},
    {type: ETHER_TYPE_UNKNOWN, shortName: "ETHER_TYPE_UNKNOWN", longName: 'ETHER_TYPE_UNKNOWN (0x2e00)'},
];

// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
export const PROTOCOL_ICMP = 1;
export const PROTOCOL_IGMP = 2;
export const PROTOCOL_TCP = 6;
export const PROTOCOL_UDP = 17;

export const PROTOCOLS = [
    {type: PROTOCOL_TCP, shortName: "TCP", longName: 'Transmission Control Protocol'},
    {type: PROTOCOL_UDP, shortName: "UDP", longName: 'User Datagram Protocol'},
];

