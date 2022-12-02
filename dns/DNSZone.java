package dns;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.lang.NumberFormatException;
import java.util.NoSuchElementException;
import java.util.Scanner;
import java.util.*;

/**
 * Class representing a single DNS zone file.
 *
 * @version 1.0
 */
public class DNSZone {
    private int TTL;
    private HashMap<String, String> records;
    /**
     * single constructor to make a DNS Zone object given a zone file name
     *
     * @param zonefile_name the path to a file that should be in zone file format
     */
    public DNSZone(String zonefile_name) {
        parseZoneFile(zonefile_name);
    }

    private void parseZoneFile(String zonefile_name) {
        try {
            File zonefile = new File(zonefile_name);
            Scanner sc = new Scanner(zonefile);
            records = new HashMap<String, String>();
            while(sc.hasNextLine()) {
                String[] record = sc.nextLine().split("\\s+");
                if (record.length == 1) { 
                    TTL = Integer.parseInt(record[0]);
                } else if (record.length == 5) {
                    TTL = Integer.parseInt(record[1]);
                    records.put("TTL", Integer.toString(TTL));
                    records.put("CLASS", record[2]);
                    records.put("TYPE", record[3]);
                    records.put(record[0], record[4]);
                } else {
                    System.out.println("Informat zone file format!!!");
                    System.exit(0);
                }
            }
        } catch (FileNotFoundException e) {
            System.out.println("No DNS zone file found.");
            System.exit(0);
        }
    }

    /**
     * get the global TTL for the entire zone
     * 
     * @return the global TTL
     */
    public int getTTL() {
        return TTL;
    }

    /**
     * find a record given the name, type, and class
     *
     * @param   name    the hostname to lookup
     * @param   type    the record type to lookup; must be "A"
     * @param   rclass  the record class to lookup; must be "IN"
     * @return          null if record doesn't exit or type/class are invalid; the IP (as a string) otherwise
     */
    public String getRecord(String name, String type, String rclass) {
        if (records.isEmpty() || (!(records.containsKey(name))) || (!(records.get("TYPE").equals(type))) || (!(records.get("CLASS").equals(rclass)))) {
            return null;
        } else {
            String IP = records.get(name);
            return IP;
        }
    }
}
