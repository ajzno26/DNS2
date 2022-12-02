package dns;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

/**
 * Class representing a DNS Server.
 *
 * @version 1.0
 */
public class DNSServer {
    
    /**
     * DNS uses port UDP port 53 for the server
     */
    final private int PORT = 53;

    /**
     * set the maximum packet size to be 1400 bytes for DNS messages
     */
    final private int MAX_SIZE = 1400;

    /**
     * this server will handle requests for a single zone/domain
     */
    private DNSZone zone;

    /**
     * Required constructor that simply prints out some messages about the server.
     *
     * @param zone a DNSZone object that has already been constructed
     */
    public DNSServer(DNSZone zone) {
        this.zone = zone;

        System.out.printf("Starting server on port %d%n", PORT);
        System.out.printf("Using default TTL %d seconds%n", zone.getTTL());
    }

    /**
     * handle one DNS request message
     *
     * @param   requestPkt  the UDP packet containing the DNS request
     * @return              a UDP packet containing the DNS response  
     */
    private DatagramPacket handleMessage(DatagramPacket requestPkt) {
        // create a DNS Message object that will parse the request packet data
        var requestMessage = new DNSMessage(requestPkt);

        // print the request message contents
        System.out.println(requestMessage);

        // look for the records in our zone
        var ip = zone.getRecord(requestMessage.getQuestionName(), requestMessage.getQuestionType(), requestMessage.getQuestionClass());

        // make a response message
        var responseMessage = new DNSMessage(requestMessage, ip, zone.getTTL());

        // print the response message contents
        System.out.println(responseMessage);

        // make and return a response packet
        return new DatagramPacket(responseMessage.getData(), responseMessage.getDataLength(), requestPkt.getSocketAddress());
    }

    /**
     * Open a socket to receive UDP packets and handle those packets
     */
    public void run() {
        // open the socket, ensure it will close when the try block finishes
        try (
            // listen on localhost only
            var sock = new DatagramSocket(PORT, InetAddress.getLoopbackAddress());
        ) {
            // keep reading packets one at a time, forever
            while(true) {
                // packet to store the incoming message
                var in_packet = new DatagramPacket(new byte[MAX_SIZE], MAX_SIZE);

                // blocking call, read one packet
                sock.receive(in_packet);

                System.out.println("Request received from " + in_packet.getSocketAddress());

                // handle this packet; given the request packet, will return a response packet
                var out_packet = handleMessage(in_packet);

                // send the response
                sock.send(out_packet);
            }
        } catch(IOException e) {
            // Have to catch IOexceptions for most socket calls
            System.out.println("Network error!");
        }
    }

    /**
     * Server starting point
     *
     * @param args should contain a single value, the filename of the zone file
     */
    public static void main(String[] args) {
        // must have exactly a single command line argument
        if(args.length != 1) {
            System.out.println("Usage: sudo java dns.DNSServer zone_file");
            System.exit(0);
        }

        // make the zone, which will exit() if the file is invalid in any way
        var zone = new DNSZone(args[0]);

        // make the server object then start listening for DNS requests
        var server = new DNSServer(zone);
        server.run();
    }
}
