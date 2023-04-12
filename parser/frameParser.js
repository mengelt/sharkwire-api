import { ETHER_TYPE_ARP, ETHER_TYPE_IP4, ETHER_TYPE_IP6, ETHER_TYPE_UNKNOWN, PROTOCOL_ICMP, PROTOCOL_IGMP, PROTOCOL_TCP, PROTOCOL_UDP, UDP_PACKET_TYPE_DEFAULT, UDP_PORTS } from './consts.js';
//import { uncommonUdpPorts } from './consts.js'

//let file = 'test-pcaps/home-network-monday-morning.pcap';
//let file = 'test-pcaps/NK.pcap';

// https://wiki.wireshark.org/Development/LibpcapFileFormat
// https://www.scadacore.com/tools/programming-calculators/online-hex-converter/
// https://www.tcpdump.org/linktypes.html

const ENDIAN = {BIG: "BIG", LITTLE: "LITTLE"};

const PCAP_HEADER_MAGIC_NUMBER_B8_LE = "a1b2c3d4"
const PCAP_HEADER_MAGIC_NUMBER_B8_BE = "d4c3b2a1"

function getSystemEndianness() {
    const buffer = new ArrayBuffer(2);
    const view = new DataView(buffer);
    view.setUint16(0, 0x1234, true);  
    const isLittleEndian = (new Uint8Array(buffer))[0] === 0x34;
    return isLittleEndian ? ENDIAN.LITTLE : ENDIAN.BIG;
}

function readBytesFromBuffer(buffer, start, numBytes) {
  
    if (start < 0 || start >= buffer.length) {
      throw new Error('Start index is out of bounds');
    }
  
    if (numBytes < 0 || start + numBytes > buffer.length) {
      throw new Error(`Invalid number of bytes to read. Starting at ${start}, requested ${numBytes}. Buffer length is ${buffer.length}`);
    }
  
    const slicedBuffer = buffer.slice(start, start + numBytes);
    return slicedBuffer;
}

function readBytesAndConvertToIP(buffer, offset) {
    if (buffer.length < offset + 4) {
      throw new Error('Not enough data in the buffer.');
    }
  
    const bytes = [];
    for (let i = 0; i < 4; i++) {
      bytes.push(buffer[offset + i]);
    }
  
    return bytes.join('.');
}

function readCharsAsHex(buffer, start, numChars) {


  
    if (start < 0 || start >= buffer.length) {
      throw new Error('Start index is out of bounds');
    }
  
    if (numChars < 0 || start + numChars > buffer.length) {
      throw new Error('Invalid number of characters to read');
    }
  
    const slicedBuffer = buffer.slice(start, start + numChars);
    const hexString = slicedBuffer.toString('hex');
    return hexString;
  }

function createWordFromArray(array) {
    
    if (!Array.isArray(array)) {
      throw new Error('Input must be an array');
    }
  
    if (array.length !== 2) {
      throw new Error('Array length must be 2');
    }
  
    let result = (array[0] << 8) | array[1];
    return result;

}

function createDoubleWordFromArray(array) {

    if (!Array.isArray(array)) {
      throw new Error('Input must be an array');
    }
  
    if (array.length !== 4) {
      throw new Error('Array length must be 4');
    }
  
    let result = (array[0] << 24) | (array[1] << 16) | (array[2] << 8) | array[3];
    return result;

}



const readFileHeader = (data) => {

    // 04 bytes - header (0-3) magic number
    // 02 bytes - version major (4-5)
    // 02 bytes - version minor (6-7)
    // 04 bytes - thiszone (8-11) (GMT conversion) set to 0 in practice
    // 04 bytes - sigfigs (12-15) set to 0 in practice
    // 04 bytes - (16-19) max length of captured packets, in octets
    // 04 bytes - (20-23) networkLinkType
    
    // https://ask.wireshark.org/question/15501/what-is-the-endianness-of-captured-packet-headers/

    let endian = null;
    let magicNumber = readCharsAsHex(data, 0, 4);

    if ( magicNumber === PCAP_HEADER_MAGIC_NUMBER_B8_BE ) {
        endian = ENDIAN.BIG;
    } else if ( magicNumber === PCAP_HEADER_MAGIC_NUMBER_B8_LE ) {
        endian = ENDIAN.LITTLE;
    } else {
        throw new Error('Unable to read magic number from PCAP.');
    }


    let fileHeader = {
        endian, 
        magicNumber: readCharsAsHex(data, 0, 4),
        versionMajor: createWordFromArray(Array.from(endianize(readBytesFromBuffer(data, 4, 2), endian))),
        versionMinor: createWordFromArray(Array.from(endianize(readBytesFromBuffer(data, 6, 2)))),
        timeZone: createDoubleWordFromArray(Array.from(endianize(readBytesFromBuffer(data, 8, 4)))),
        sigFigs: createDoubleWordFromArray(Array.from(endianize(readBytesFromBuffer(data, 12, 4)))),
        octetLength: createDoubleWordFromArray(Array.from(endianize(readBytesFromBuffer(data, 16, 4)))),
        networkLinkType: createDoubleWordFromArray(Array.from(endianize(readBytesFromBuffer(data, 20, 4)))),
    }
    return fileHeader;
}



const reverseBuffer = (buffer) => {
  
    const length = buffer.length;
    const reversedBuffer = Buffer.allocUnsafe(length);
  
    for (let i = 0; i < length; i++) {
      reversedBuffer[i] = buffer[length - 1 - i];
    }
  
    return reversedBuffer;
}

function getCurrentTimeString() {
    const now = new Date();
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    return `${hours}:${minutes}:${seconds}`;
}

const endianize = (buffer, fileEndian) => {
    const systemEndian = getSystemEndianness();

    // endian-ness of file and system are the same, nothing to do
    // the endian-ness of file and system are not the same, but we only are dealing with 1 byte, nothing to do
    if ( fileEndian === systemEndian) {
        return buffer;
    }

    if ( buffer.length === 1) {
        return buffer;
    }

    return reverseBuffer(buffer);
    
}

const createFrameData = (id, source, destination, protocol, length, info, frameData) => {
    return {
        id,
        source,
        destination,
        protocol,
        length,
        info,
        frameData
    }
}


// https://wiki.wireshark.org/Development/LibpcapFileFormat#record-packet-header
const readRecordHeader = (fileEndian, fileData, start) => {

/*

  typedef struct pcaprec_hdr_s {
          guint32 ts_sec;         // timestamp seconds 
          guint32 ts_usec;        // timestamp microseconds
          guint32 incl_len;       // incl_len: the number of bytes of packet data actually captured and saved in the file. This value should never become larger than orig_len or the snaplen value of the global header.
          guint32 orig_len;       // orig_len: the length of the packet as it appeared on the network when it was captured. If incl_len and orig_len differ, the actually saved packet size was limited by snaplen.
  } pcaprec_hdr_t;

*/

    let recordHeader = {
        timestampSeconds: createDoubleWordFromArray(
                            Array.from(
                                endianize(
                                    readBytesFromBuffer(fileData, start, 4), fileEndian
                                )
                            )
                          ),
        timeStampMicroSeconds: createDoubleWordFromArray(Array.from(endianize(readBytesFromBuffer(fileData, start + 4, 4), fileEndian))),
        savedPacketLength: createDoubleWordFromArray(Array.from(endianize(readBytesFromBuffer(fileData, start + 8, 4), fileEndian))),
        actualPacketLength: createDoubleWordFromArray(Array.from(endianize(readBytesFromBuffer(fileData, start + 12, 4), fileEndian)))
    }
    return recordHeader;

}

// takes a Buffer from a .pcap file and returns raw frames
export const getFramesFromBuffer = (buffer) => {
    let fileHeader = readFileHeader(readBytesFromBuffer(buffer, 0, 24));  
    let allFrameData = readBytesFromBuffer(buffer, 24, buffer.length-24);
    
    let pointer = 0;
    let allFrames = [];

    
    while (pointer < allFrameData.length) {

        // read record header, pointer += 16
        let recordHeader = readRecordHeader(fileHeader.endian, allFrameData, pointer);
        pointer += 16;

        // read packet
        let frameData = readBytesFromBuffer(allFrameData, pointer, recordHeader.actualPacketLength);
        allFrames.push(
            createFrameData(allFrames.length+1,'?','?','?', recordHeader.actualPacketLength, '?', frameData)
        );

        pointer += recordHeader.actualPacketLength

    }
    return {fileHeader, bufferFrames: allFrames}
}

export const processFrames = (fileHeader, frames) => {

    let allFrames = frames.map( frame => {
        
        let newFrame = processFrame(fileHeader.endian, frame);
    
        // advance array 14 bytes from header
        newFrame.frameData = sliceBuffer(frame.frameData, 14);
    
        if ( newFrame.ethernet.type === ETHER_TYPE_IP4 ) {
            // parse the IP4 part
    
            let result = processIPv4Frame(fileHeader.endian, frame);
    
            let ipHeaderLength = result.ipHeaderLength;
    
            newFrame = result.newFrame;
    
            // advance the frame by the amount of bytes read in the ip header
            newFrame.frameData = sliceBuffer(newFrame.frameData, ipHeaderLength);
    
            if ( newFrame.ipv4.protocol === PROTOCOL_TCP ) {
                
                newFrame = processTcpFrame(fileHeader.endian, newFrame);
    
            } else if ( newFrame.ipv4.protocol === PROTOCOL_UDP  ) {
                
                newFrame = processUdpFrame(newFrame);
                // TODO, if we are going to process the UDP payload, do it here
    
            } else if ( newFrame.ipv4.protocol === PROTOCOL_ICMP  ) {
    
                // TODO, pingy
    
            } else if ( newFrame.ipv4.protocol === PROTOCOL_IGMP  ) {
    
                // TODO, pingy
    
            }
            
        } else if ( newFrame.ethernet.type === ETHER_TYPE_IP6 ) {
    
            // parse ipv6
            // let result = processIPv6Frame(fileHeader.endian, frame);
    
        } else if ( newFrame.ethernet.type === ETHER_TYPE_ARP ) {
    
            newFrame = processArpFrame(fileHeader.endian, frame);
    
        } else if ( newFrame.ethernet.type === ETHER_TYPE_UNKNOWN ) {
        
            // nothing to do, unsure how to handle
    
        } else {
    
            
            newFrame = frame;
        }
    
        return newFrame;
        
    })
    
    return allFrames;

}

function bufferToHexString(buffer) {
    let hexString = '';
    for (let i = 0; i < buffer.length; i++) {
      hexString += buffer[i].toString(16).padStart(2, '0');
    }
    return `0x${hexString}`;
  }
  
  function getTopNibble(byte) {
    if (byte < 0 || byte > 255) {
      throw new Error('Input should be a valid byte (0-255).');
    }
    return (byte & 0xF0) >> 4;
  }

  function getBottomNibble(byte) {
    if (byte < 0 || byte > 255) {
      throw new Error('Input should be a valid byte (0-255).');
    }
    return byte & 0x0F;
  }

  
  const processArpFrame = (endian, frame) => {

    frame.arp = {};
    
    // arp.hw.type = 2 bytes
    frame.arp.hardwareType = null;

    // arp.proto.type = 2 bytes
    frame.arp.protoType = null;

    // arp.proto.size = 1 byte
    frame.arp.protoSize = null;

    // arp.opcode = 2 bytes
    frame.arp.opcode = null;

    // arp.src.hw_mac = 6 bytes
    frame.arp.srcHwMac = null;

    // arp.src.proto_ipv4 = 4 bytes
    frame.arp.senderIp = null;

    // arp.dst.hw_mac = 6 bytes
    frame.arp.dstHwMac = null;

    // arp.dst.proto_ipv4 = 4 bytes
    frame.arp.targetIp = null;


  }

const processIPv4Frame = (endian, frame) => {

    frame.ipv4 = {};

    // ip.version = 1 byte
    frame.ipv4.version = getTopNibble(Array.from( readBytesFromBuffer(frame.frameData, 0, 1)))
    
    // ip.headerLength = 1 byte (count of 32 bit words, a 5 would be 20 bytes)
    frame.ipv4.headerLength = getBottomNibble(Array.from( readBytesFromBuffer(frame.frameData, 0, 1))) * 4;

    // ip.dsField = 1 byte
    frame.ipv4.dsField = Array.from( readBytesFromBuffer(frame.frameData, 1, 1))[0];

    // ip.totalLength = 2 bytes    
    frame.ipv4.totalLength = createWordFromArray(Array.from(readBytesFromBuffer(frame.frameData, 2, 2)));

    // ip.id = 2 bytes
    frame.ipv4.id = readCharsAsHex(frame.frameData,0,6);(Array.from(readBytesFromBuffer(frame.frameData, 4, 2)));

    // ip.flags + ip_frag_offset = 2 bytes (3 bits + 13 bits)
    frame.ipv4.fragOffset = createWordFromArray(Array.from(readBytesFromBuffer(frame.frameData, 6, 2)));

    // ip.ttl = 1 byte
    frame.ipv4.ttl = Array.from( readBytesFromBuffer(frame.frameData, 8, 1))[0];

    // ip.proto = 1 byte
    frame.ipv4.protocol = Array.from( readBytesFromBuffer(frame.frameData, 9, 1))[0];

    // ip.checksum = 2 bytes
    frame.ipv4.checksum = readCharsAsHex(frame.frameData,10,2);

    // ip.src = 4 bytes
    frame.ipv4.sourceAddress = readBytesAndConvertToIP(frame.frameData, 12);  

    // ip.dst = 4 bytes
    frame.ipv4.destinationAdress = readBytesAndConvertToIP(frame.frameData, 16);

    return { ipHeaderLength: frame.ipv4.headerLength, newFrame: frame }

}

const processIPv6Frame = (endian, frame) => {

  frame.ipv6 = {};

  // ipv6.version = 1 byte
  frame.ipv6.version = getTopNibble(Array.from( readBytesFromBuffer(frame.frameData, 0, 1)))

  // ipv6.tclass = 4 bytes
  frame.ipv6.tclass = createDoubleWordFromArray(Array.from(readBytesFromBuffer(frame.frameData, 1, 4)));
  

  return { ipHeaderLength: frame.ipv6.headerLength, newFrame: frame }

}

function sliceBuffer(buffer, offset) {
    if (offset < 0 || offset >= buffer.length) {
      throw new Error('Offset is out of bounds.');
    }
    return Buffer.from(buffer.slice(offset));
  }

const processFrame = (endian, frame) => {

    // ethernet II, 14 bytes
    // 6 eth.src (mac)
    // 6 eth.dest (mac)
    // 2 eth.type

    // https://en.wikipedia.org/wiki/Ethernet_frame

    frame.ethernet = {};
    frame.ethernet.src = readCharsAsHex(frame.frameData,0,6);
    frame.ethernet.dest = readCharsAsHex(frame.frameData,6,6);

    // https://en.wikipedia.org/wiki/EtherType
    // network byte order
    frame.ethernet.type = bufferToHexString(readBytesFromBuffer(frame.frameData, 12, 2), endian);

    return frame;

}


const processTcpFrame = (endian, frame) => {

  frame.tcp = {};

  frame.tcp.destinationPort = createWordFromArray(Array.from(readBytesFromBuffer(frame.frameData, 0, 2)));
  frame.tcp.sourcePort = createWordFromArray(Array.from(readBytesFromBuffer(frame.frameData, 2, 2)));

  
  
  //frame.tcp.sequenceNumber = createDoubleWordFromArray(Array.from(readBytesFromBuffer(frame.frameData, 4, 4)));
  frame.tcp.sequenceNumber = createDoubleWordFromArray(Array.from(endianize(readBytesFromBuffer(frame.frameData, 4, 4))));
  
  frame.tcp.acknowledgementNumber = null;
  frame.tcp.headerLength = null;
  frame.tcp.flags = {};
  frame.tcp.flags.reserved = null;
  frame.tcp.flags.accurateECN = null;
  frame.tcp.flags.congestionWindowReduced = null;
  frame.tcp.flags.ecnEcho = null;
  frame.tcp.flags.urgent = null;
  frame.tcp.flags.acknoledgement = null;
  frame.tcp.flags.push = null;
  frame.tcp.flags.reset = null;
  frame.tcp.flags.syn = null;
  frame.tcp.flags.fin = null;

    return frame;

}

const processUdpFrame = (frame) => {

    const getPacketTypeByDestPort = destPort => {
        let portType = UDP_PORTS.find(f => f.port === destPort);
        if ( typeof portType === "undefined" ) {
            return UDP_PACKET_TYPE_DEFAULT;
        }
        return portType.shortName;
    }

    frame.udp = {}
    
    frame.udp.sourcePort = createWordFromArray(Array.from(readBytesFromBuffer(frame.frameData, 0, 2)));
    frame.udp.destinationPort = createWordFromArray(Array.from(readBytesFromBuffer(frame.frameData, 2, 2)));
    frame.udp.length = createWordFromArray(Array.from(readBytesFromBuffer(frame.frameData, 4, 2)));
    frame.udp.checksum = createWordFromArray(Array.from(readBytesFromBuffer(frame.frameData, 6, 2)));
    frame.udp.payload = null; // TODO
    frame.udp.udpPacketType = getPacketTypeByDestPort( frame.udp.destinationPort )

    

    return frame;

}

function isIpInRange(ip, startIp, endIp) {
  function ipStringToInteger(ipString) {
    const octets = ipString.split('.');
    return (
      (parseInt(octets[0], 10) << 24) |
      (parseInt(octets[1], 10) << 16) |
      (parseInt(octets[2], 10) << 8) |
      parseInt(octets[3], 10)
    );
  }

  const ipInteger = ipStringToInteger(ip);
  const startIpInteger = ipStringToInteger(startIp);
  const endIpInteger = ipStringToInteger(endIp);

  return ipInteger >= startIpInteger && ipInteger <= endIpInteger;
}


const hasForeignPing = frames => {

  let nkRange = ['175.45.176.0', '175.45.179.255']

  
  let pings = frames.filter(f => {
    

    let id = f?.id || null;
    console.info(':', id);

    if ( id !== null && id === 20 ) {
      console.info('eh?')
    }

    let source = f?.ipv4?.sourceAddress || null;
    if (source !== null && f.ipv4.protocol === PROTOCOL_ICMP) {
      let chunks = parseInt( source.split('.').join('') )
      
      return isIpInRange(source, nkRange[0], nkRange[1])

    }  
    return false
  })
  
  return pings

}

//let foreignPings = hasForeignPing(allFrames)
//console.info(foreignPings)

/*
let udpPortAnalysis = uncommonUdpPorts(allFrames);
console.info({e: udpPortAnalysis.susFrames.map(m => m.udp.destinationPort)})

*/


/*
logMessage(`Starting analysis from ${allFrames.length} frames...`)
allFrames = allFrames.map( frame => {

    let newFrame = processFrame(fileHeader.endian, frame);

    // advance array 14 bytes from header
    newFrame.frameData = sliceBuffer(frame.frameData, 14);

    if ( newFrame.ethernet.type === ETHER_TYPE_IP4 ) {
        // parse the IP4 part

        let result = processIPv4Frame(fileHeader.endian, frame);

        let ipHeaderLength = result.ipHeaderLength;

        newFrame = result.newFrame;

        // advance the frame by the amount of bytes read in the ip header
        newFrame.frameData = sliceBuffer(newFrame.frameData, ipHeaderLength);

        if ( newFrame.ipv4.protocol === PROTOCOL_TCP ) {
            
            newFrame = processTcpFrame(fileHeader.endian, newFrame);

        } else if ( newFrame.ipv4.protocol === PROTOCOL_UDP  ) {
            
            newFrame = processUdpFrame(newFrame);
            // TODO, if we are going to process the UDP payload, do it here

        } else if ( newFrame.ipv4.protocol === PROTOCOL_ICMP  ) {

            // TODO, pingy

        } else if ( newFrame.ipv4.protocol === PROTOCOL_IGMP  ) {

            // TODO, pingy

        } else (
            console.info( chalk.red('i cant handle newFrame.ipv4.protocol =', newFrame.ipv4.protocol, 'yet'))
        )
        
    } else if ( newFrame.ethernet.type === ETHER_TYPE_IP6 ) {

        // parse ipv6
        let result = processIPv6Frame(fileHeader.endian, frame);

    } else if ( newFrame.ethernet.type === ETHER_TYPE_ARP ) {

        newFrame = processArpFrame(fileHeader.endian, frame);

    } else if ( newFrame.ethernet.type === ETHER_TYPE_UNKNOWN ) {
    
        // nothing to do, unsure how to handle

    } else {

        console.info(chalk.red('i cant handle a newFrame.ethernet.type=', newFrame.ethernet.type, 'yet!'))
        newFrame = frame;
    }

    return newFrame;
    
})
*/