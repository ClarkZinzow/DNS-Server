package edu.wisc.cs.sdn.simpledns;

import java.io.File;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import edu.wisc.cs.sdn.simpledns.packet.DNS;
import edu.wisc.cs.sdn.simpledns.packet.DNSQuestion;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataAddress;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataName;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataText;
import edu.wisc.cs.sdn.simpledns.packet.DNSResourceRecord;

/**
 * A DNS server that accepts queries from clients and issues queries to other DNS servers in order to respond to client queries.
 *
 */
public class SimpleDNS {

    private final static int listenPort = 8053; // UDP packet listen port.
    private final static int sendPort = 53; // Send port.
    private static String csvFileName; // File name of csv file.
    private static DatagramSocket dnsSocket; // DNS socket.
    private static InetAddress selfAddress; // Address of this server.
    private static InetAddress rootServerAddress; // Address of root server.
    private static DatagramPacket firstQueryPacket, replyPacket; // First client query packet and the reply packet.
    private static byte[] firstQueryData; // Byte array of data for first query.
    private static HashMap<String,String> ipZoneMap = new HashMap<String,String>(); // Map of IP zones.
    private static List<Integer> netmaskList = new ArrayList<Integer>(); // Netmask list.

    /*
     * Resolves a query nonrecursively.
     *
     * @param DatagramPacket queryPacket   The query packet.
     * @param DatagramPacket dnsRequestPacket   The DNS request packet.
     * @return DatagramPacket receivePacket   The resolved packet
     *
     */
	
    private static DatagramPacket nonrecursivelyResolve(DatagramPacket queryPacket, DNS dnsRequestPacket) throws Exception {
		
        DatagramPacket newQueryPacket, receivePacket; // New query packet and the received packet
        byte[] receiveData = new byte[4096]; // Byte array of receive data.
		
        newQueryPacket = new DatagramPacket(queryPacket.getData(), queryPacket.getLength(), rootServerAddress, sendPort);
        receivePacket = new DatagramPacket(receiveData, receiveData.length);
		
        dnsSocket.send(newQueryPacket);
        dnsSocket.receive(receivePacket);
		
        System.out.println("\nReceived the packet");
		
        return receivePacket;
    }

    /*
     * Resolves a query recursively.
     *
     * @param DatagramPacket queryPacket   The query packet.
     * @param DatagramPacket dnsRequestPacket   The DNS request packet.
     * @return DatagramPacket finalReplyPacket   The desired return packet.
     */
	
    private static DatagramPacket recursivelyResolve(DatagramPacket queryPacket,DNS dnsRequestPacket) throws Exception {
		
        DatagramPacket newQueryPacket = null; // New query packet.
        DatagramPacket receivePacket = null; // Receive packet.
        DatagramPacket finalReplyPacket = null; // Packet to be returned.
	DNS dnsQueryPacket,dnsReceivePacket;
	boolean resolved = false;
	byte[] receiveData = new byte[4096];
	List<DNSResourceRecord> cnameList = new ArrayList<DNSResourceRecord>();
	List<DNSResourceRecord> lastAuthList = new ArrayList<DNSResourceRecord>();
	List<DNSResourceRecord> lastAddList = new ArrayList<DNSResourceRecord>();
		
	newQueryPacket = new DatagramPacket(queryPacket.getData(), queryPacket.getLength(), rootServerAddress, sendPort);
	receivePacket = new DatagramPacket(receiveData,receiveData.length);
	dnsSocket.send(newQueryPacket);
		
	while(!resolved) {	
			
            dnsSocket.receive(receivePacket);
			
            // Check if the data received has an answer or if it should be resolved.
            dnsReceivePacket = DNS.deserialize(receivePacket.getData(),receivePacket.getData().length);
	    List<DNSResourceRecord> authorityList = dnsReceivePacket.getAuthorities();
            List<DNSResourceRecord> additionalList = dnsReceivePacket.getAdditional();
			
            // Check if the authority section and additional section contains any data.
            if(authorityList.size() > 0) {
		boolean listContainsNonSOA = false;
		for(int i = 0; i < authorityList.size(); i++) {
		    if(authorityList.get(i).getType() == DNS.TYPE_A) {
			listContainsNonSOA = true;
			break;
		    }
		    else if(authorityList.get(i).getType() == DNS.TYPE_AAAA) {
			listContainsNonSOA = true;
			break;
		    }
		    else if(authorityList.get(i).getType() == DNS.TYPE_NS) {
			listContainsNonSOA = true;
			break;
		    }
		    else if(authorityList.get(i).getType() == DNS.TYPE_CNAME) {
			listContainsNonSOA = true;
			break;
		    }
		}
		if(listContainsNonSOA) {
		    lastAuthList = authorityList;
		}
	    }
	    if(additionalList.size() > 0) {
		lastAddList = additionalList;
	    }
			
	    if(dnsReceivePacket.getAnswers().size() == 0) {
		// No answers at this point.		
		// Check the authority section and get the next NS INET Address.
		InetAddress nextNSAddress = null;
		DNSResourceRecord authRR = null, addRR = null;
		boolean matchFound = false;
				
		for(int i = 0; i < authorityList.size(); i++) {
		    authRR = authorityList.get(i);
					
		    // Check if there is a corresponding IP in the Additional Section
		    for(int j = 0; j < additionalList.size(); j++) {
			addRR = additionalList.get(j);
			DNSRdataName nsName = (DNSRdataName)authRR.getData();
			if(authRR.getType() == DNS.TYPE_NS && (addRR.getName().equals(nsName.getName())) && (addRR.getType() == DNS.TYPE_A)) {
			    // Match the name server with an IP address.
			    matchFound = true;
			    break;
			}
		    }
			
		    if(matchFound) {
			break;
		    }
		}
				
		if(matchFound) {
		    // Get the IP address.
		    DNSRdataAddress dnsRdata = (DNSRdataAddress)addRR.getData();
		    nextNSAddress = dnsRdata.getAddress();
		}
		else {
		    // Returneturn the packet.
		    DNS finalDNSPacket = new DNS();
					
		    List<DNSResourceRecord> finalAnswerList = dnsReceivePacket.getAnswers();
		    List<DNSResourceRecord> finalAuthList = dnsReceivePacket.getAuthorities();
		    List<DNSResourceRecord> finalAddList = dnsReceivePacket.getAdditional();
					
		    // Find if the authority section and additional section contains data
		    // Add any CNAME that was resolved
		    for(int i = 0; i < cnameList.size(); i++) {
			finalAnswerList.add(0, cnameList.get(i));
		    }
		    finalDNSPacket.setQuestions(dnsRequestPacket.getQuestions());
		    finalDNSPacket.setAnswers(finalAnswerList);
		    for(int i = 0; i < finalAuthList.size(); i++) {
			if((finalAuthList.get(i).getType() != DNS.TYPE_A) && (finalAuthList.get(i).getType() != DNS.TYPE_AAAA) && (finalAuthList.get(i).getType() != DNS.TYPE_NS) && (finalAuthList.get(i).getType() != DNS.TYPE_CNAME)) {
			    finalAuthList.remove(i);
			}
		    }
		    for(int i = 0; i < finalAddList.size(); i++){
			if((finalAddList.get(i).getType() != DNS.TYPE_A) && (finalAddList.get(i).getType() != DNS.TYPE_AAAA) && (finalAddList.get(i).getType() != DNS.TYPE_NS) && (finalAddList.get(i).getType() != DNS.TYPE_CNAME)) {
			    finalAddList.remove(i);
			}
		    }

		    if(finalAuthList.size() == 0) {
			finalAuthList = lastAuthList;
		    }
		    if(finalAddList.size() == 0) {
			finalAddList = lastAddList;
		    }
		
		    finalDNSPacket.setAuthorities(finalAuthList);
		    finalDNSPacket.setAdditional(finalAddList);
		    setDNSReplyFlags(finalDNSPacket);
		    finalDNSPacket.setId(dnsRequestPacket.getId());
		    finalReplyPacket = new DatagramPacket(finalDNSPacket.serialize(),finalDNSPacket.getLength());
					
		    return finalReplyPacket;
		}
				
		// Form the Datagram Packet by copying the question from the previous packet.
		newQueryPacket = new DatagramPacket(newQueryPacket.getData(), newQueryPacket.getLength(), nextNSAddress, sendPort);
		dnsSocket.send(newQueryPacket);
	    }
	    else {
		// Got answer.
		// Check if it is only CNAME.
		List<DNSResourceRecord> answerList = dnsReceivePacket.getAnswers();
		DNSResourceRecord answer = null;
		answer = answerList.get(0);
		
		if(answer.getType() == DNS.TYPE_CNAME){
		
		    // CNAME is received, resolve again looking at authority section.
		    cnameList.add(answer);
					
		    // Create a new question.
		    DNSQuestion newQuestion = new DNSQuestion();
		    DNSRdataName dnsRdataname = (DNSRdataName)answer.getData();
		    newQuestion.setName(dnsRdataname.getName());
		    newQuestion.setType(dnsReceivePacket.getQuestions().get(0).getType());
					
		    // Form the new DNS query.
		    dnsQueryPacket = new DNS();
		    
		    // Set the flags.
		    setDNSRequestFlags(dnsQueryPacket);
					
		    // Set the id to the original id.
		    dnsQueryPacket.setId(dnsRequestPacket.getId());
					
		    // Set the question.
		    List<DNSQuestion> newQuestionList = new ArrayList<DNSQuestion>();
		    newQuestionList.add(newQuestion);
		    dnsQueryPacket.setQuestions(newQuestionList);
					
		    // Form the Datagram Packet and send to root server.
		    newQueryPacket = new DatagramPacket(dnsQueryPacket.serialize(), dnsQueryPacket.getLength(), rootServerAddress, sendPort);
		    dnsSocket.send(newQueryPacket);
					
		}
		else {
		    resolved = true;
		    List<DNSResourceRecord> finalAnswerList = dnsReceivePacket.getAnswers();
		
		    // Add TXT records if possible.
		    if(dnsRequestPacket.getQuestions().get(0).getType() == DNS.TYPE_A) {
			addTXTRecords(finalAnswerList);
		    }
					
		    // Add any CNAME that was resolved.
		    for(int i = 0; i < cnameList.size(); i++) {
			finalAnswerList.add(0, cnameList.get(i));
		    }
					
		    // Check if the packet contains authority and additional section data.
		    
		    if(dnsReceivePacket.getAuthorities().size() == 0){
			dnsReceivePacket.setAuthorities(lastAuthList);
		    }
					
		    if(dnsReceivePacket.getAdditional().size() == 0){
			dnsReceivePacket.setAdditional(lastAddList);
		    }
					
		    // Set the new answers.
		    dnsReceivePacket.setAnswers(finalAnswerList);
					
		    // Set it back to original question.
		    dnsReceivePacket.setQuestions(dnsRequestPacket.getQuestions());
					
		    // Set the appropriate flags.
		    setDNSReplyFlags(dnsReceivePacket);
					
		    // Set up the Datagram Packet to be returned.
		    finalReplyPacket = new DatagramPacket(dnsReceivePacket.serialize(),dnsReceivePacket.getLength());
		}
	    }
	}
		
	return finalReplyPacket;
    }

    /*
     * Creates the csv map.
     */
	
    private static void formcsvMap()throws Exception{
	int i = 0;
	int slashPosition;
	Scanner scnr = new Scanner(new File(csvFileName));
	String ip;
	String region;
	String line;
		
	while(scnr.hasNext()) {
	    line = scnr.nextLine();
	    ip = line.substring(0, line.indexOf(','));
	    region = line.substring(line.indexOf(',')+1, line.length());
	    slashPosition = ip.indexOf("/",0);
	    ipZoneMap.put(ip.substring(0,slashPosition), region);
	    netmaskList.add(Integer.parseInt(ip.substring(slashPosition+1, ip.length())));
	}
	scnr.close();
    }

    /*
     * Adds the TXT records.
     */
	
    private static void addTXTRecords(List<DNSResourceRecord> answerList) throws Exception{
		
	int i;
	DNSRdataAddress ansip;
		
	for(i = 0; i < answerList.size(); i++) {
	    // Find if the record is of type A.
	    if(answerList.get(i).getType() != DNS.TYPE_A){
		continue;
	    }
			
	    // Find if there is a match for the given IP.
	    ansip = (DNSRdataAddress)answerList.get(i).getData();
	    Iterator<Map.Entry<String, String>> it  = ipZoneMap.entrySet().iterator();
	    Map.Entry<String, String> me;
	    int j = 0;
			
	    while(it.hasNext()) {
		me = it.next();
				
		if(isMatch(ansip.toString(),me.getKey(),netmaskList.get(j))) {
		    
		    // Found Match.
		    // Add a TXT DNSResourceRecord to answerList.
		    DNSResourceRecord dnsrr = new DNSResourceRecord();
		    dnsrr.setName(answerList.get(i).getName());
		    dnsrr.setTtl(3600);
		    dnsrr.setType(DNS.TYPE_TXT);
		    DNSRdataText dnsrdatatext= new DNSRdataText(me.getValue()+"-"+ansip.toString());
		    dnsrr.setData(dnsrdatatext);
		    answerList.add(dnsrr);
		    break;
		}
		j++;
	    }
	}
    }

    /*
     * Check if is match.
     */
	
    private static boolean isMatch(String networkAddress, String resolvedIp, int netmask) throws Exception{
		
	int count = 0;
       	byte[] networkAddBytes = InetAddress.getByName(networkAddress).getAddress();
	byte[] resAddBytes = InetAddress.getByName(resolvedIp).getAddress();
	byte check1 = networkAddBytes[count/8];
	byte check2 = resAddBytes[count/8];
	int bmask = 128;
	byte bitmask = (byte)(bmask);
		
	// Check if the the next netmask bytes are the same
	while(count<netmask) {
	    
	    if((check1 & bitmask) == (check2 & bitmask)) {
		count++;
		if(count%8 == 0) {
		    bmask = 128;
		    bitmask = (byte)(bmask);
		    check1 = networkAddBytes[count/8];
		    check2 = resAddBytes[count/8];
		}
		else{
		    bmask /= 2;
		    bitmask = (byte)bmask;
		}
	    }
	    else {
		// No match found.
		break;
	    }
	}
	return count == netmask; // True => match found, false => not.
    }
	
    private static void setDNSRequestFlags(DNS dnsRequestPacket) {
		
	// Set the flags
	dnsRequestPacket.setQuery(true);
	dnsRequestPacket.setOpcode((byte)0);
	dnsRequestPacket.setTruncated(false);
	dnsRequestPacket.setRecursionDesired(true);
	dnsRequestPacket.setAuthenicated(false);
    }
    
    private static void setDNSReplyFlags(DNS dnsReplyPacket){
	
	dnsReplyPacket.setQuery(false);
	dnsReplyPacket.setOpcode((byte)0);
	dnsReplyPacket.setAuthoritative(false);
	dnsReplyPacket.setTruncated(false);
	
	dnsReplyPacket.setRecursionAvailable(true);
	dnsReplyPacket.setRecursionDesired(true);
	dnsReplyPacket.setAuthenicated(false);
	dnsReplyPacket.setCheckingDisabled(false);
	
	dnsReplyPacket.setRcode((byte)0);
	
    }
    
    public static void main(String[] args)
    {
	if(args.length != 4 || !args[0].equals("-r") || !args[2].equals("-e")){
	    System.out.println("\nIncorrect format\nExpected: " +
			       "java edu.wisc.cs.sdn.simpledns.SimpleDNS -r <root server ip> -e <ec2 csv>");
	    System.exit(0);
	}
	
	firstQueryData = new byte[4096];
	csvFileName = args[3];
	
	try {
	    
	    formcsvMap();
	    
	    dnsSocket = new DatagramSocket(listenPort);			
	    selfAddress = InetAddress.getByName("localhost");
	    rootServerAddress = InetAddress.getByName(args[1]);
	    firstQueryPacket = new DatagramPacket(firstQueryData, firstQueryData.length);
	    
	    while(true) {
		
		dnsSocket.receive(firstQueryPacket);
		
		DNS dnsRequestPacket = DNS.deserialize(firstQueryPacket.getData(), (short)firstQueryPacket.getLength());
		System.out.println("\nReceived the dns:\n"+dnsRequestPacket.toString());
		
		// Check for flags
		if(dnsRequestPacket.getOpcode() != (byte)0){
		    System.out.println("Opcode is not 0");
		}
		
		// Now process this request
		// Construct a new DNS Query and recursively resolve
		List<DNSQuestion> dnsQuestionList = dnsRequestPacket.getQuestions();
		
		switch(dnsQuestionList.get(0).getType()){
		case DNS.TYPE_A:
		    break;
		case DNS.TYPE_AAAA:
		    break;
		case DNS.TYPE_CNAME:
		    break;
		case DNS.TYPE_NS:
		    break;
		default:
		    System.out.println("Case not compatible");
		    break;
		}
		
		if(dnsRequestPacket.isRecursionDesired()){
		    replyPacket = recursivelyResolve(firstQueryPacket, dnsRequestPacket);
		}
		else {
		    replyPacket = nonrecursivelyResolve(firstQueryPacket, dnsRequestPacket);
		}
		
		DNS dnsAnsPacket = DNS.deserialize(replyPacket.getData(), (short)replyPacket.getLength());
		
		System.out.println("\nThe final packet = " + dnsAnsPacket.toString());
		
		replyPacket.setPort(firstQueryPacket.getPort());
		replyPacket.setAddress(firstQueryPacket.getAddress());
		dnsSocket.send(replyPacket);
	    }
	}
	catch(Exception e) {
	    System.out.println("Exception: ");
	    e.printStackTrace();
	}
    }
}
