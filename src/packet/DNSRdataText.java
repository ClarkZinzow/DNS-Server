package edu.wisc.cs.sdn.simpledns.packet;

public class DNSRdataText implements DNSRdata 
{
    private String text;
    
    public DNSRdataText()
    { this.text = new String(); }
    
    public DNSRdataText(String text)
    { this.text = text;	}
    
    public String getText()
    { return this.text; }
	
    public void setText(String text)
    { this.text = text; }
    
    public byte[] serialize()
    { return DNS.serializeText(this.text); }
    
    public int getLength()
    { return this.text.length() + 1;}
    
    public String toString()
    { return this.text; }
    
}
