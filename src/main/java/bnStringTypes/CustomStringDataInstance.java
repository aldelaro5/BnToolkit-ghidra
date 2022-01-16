package bnStringTypes;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.mem.MemBuffer;

// This is a StringDataInstance that just redirects the calls to the type.
// This allows things like searching strings in the strings table.
public class CustomStringDataInstance extends StringDataInstance
{
    private AbstractBnStringDataType dt;
    private Settings settings;
    private MemBuffer buf;
    private int length;
    
    public CustomStringDataInstance(AbstractBnStringDataType bccStringDataType, Settings settings, MemBuffer buf, int length)
    {
	super(bccStringDataType, settings, buf, length);
	this.dt = bccStringDataType;
	this.settings = settings;
	this.buf = buf;
	this.length = length;
    }
    
    @Override
    public int getStringLength() 
    {
	return dt.getLength(buf, length);
    }
    
    @Override
    public String getStringValue() 
    {
	return dt.getString(buf, length);
    }

    @Override
    public String getStringRepresentation()
    {
	return dt.getRepresentation(buf, settings, length);
    }
    
    @Override
    public boolean isMissingNullTerminator() 
    {
	return dt.isMissingTerminator(buf, length);
    }
}
