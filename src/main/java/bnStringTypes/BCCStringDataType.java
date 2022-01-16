package bnStringTypes;

import java.util.HashMap;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.data.StringLayoutEnum;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

public class BCCStringDataType extends AbstractStringDataType
{
    private static final int CHAR_A = 0x5E;
    private static final int CHAR_a = 0xEB;
    
    private HashMap<Integer, String> SPECIAL_MAP = new HashMap<Integer, String>() 
    {{
        put(0x00, " ");
        put(0x79, "\u00d7");
        put(0x7C, "?");
        put(0x7D, "+");
        put(0x81, "!");
        put(0x8C, "\u2200");
        put(0x87, ".");
        put(0x99, "_");
        put(0x109, "-");
    }};

    public BCCStringDataType()
    {
	this(null);
    }

    public BCCStringDataType(DataTypeManager dtm)
    {
	super("BCCString", // data type name
	      "dbccs", // mnemonic
	      "BCCSTRING", // default label
	      "BCCSTR", // default label prefix
	      "bccs", // default abbrev label prefix
	      "BCC String (fixed length)", // description
	      USE_CHARSET_DEF_DEFAULT, // charset
	      CharDataType.dataType, // replacement data type
	      StringLayoutEnum.FIXED_LEN, // StringLayoutEnum
	      dtm);
    }

    @Override
    public DataType clone(DataTypeManager dtm)
    {
	if (dtm == getDataTypeManager())
	    return this;

	return new BCCStringDataType(dtm);
    }

    @Override
    public StringDataInstance getStringDataInstance(MemBuffer buf, Settings settings, int length) 
    {
	return new CustomStringDataInstance(this, settings, buf, length);
    }

    @Override
    public int getLength(MemBuffer buf, int maxLength)
    {
	for (int i = 0; i < 1000; i++)
	{
	    try
	    {
		int ib = buf.getByte(i) & 0xFF;
		if (ib == 0x80)
		    return buf.getByte(i - 1) * 2 + 2;
	    }
	    catch (MemoryAccessException e)
	    {
		return -1;
	    }
	}
	return -1;
    }

    @Override
    public String getRepresentation(MemBuffer buf, Settings settings, int length)
    {
	return "\"" + getString(buf, length) + "\"";
    }
    
    @Override
    public Object getValue(MemBuffer buf, Settings settings, int length) 
    {
	return getString(buf, length);
    }
    
    public Boolean isMissingTerminator(MemBuffer buf, int length)
    {
	try
	{
	    int ib = buf.getByte(length - 1) & 0xFF;
	    return ib != 0x80;
	}
	catch (MemoryAccessException e)
	{
	    return true;
	}
    }

    public String getString(MemBuffer buf, int length)
    {
	StringBuilder sb = new StringBuilder();
	for (int i = 0; i < length - 2; i += 2)
	{
	    try
	    {
		int ib = buf.getUnsignedShort(i);
		if (SPECIAL_MAP.containsKey(ib))
		    sb.append(SPECIAL_MAP.get(ib));
		else if ((ib > 0) && ib <= (10))
		    sb.append((char) ('0' + ib - 1));
		else if ((ib >= CHAR_A) && ib < (CHAR_A + 26))
		    sb.append((char) ('A' + ib - CHAR_A));
		else if ((ib >= CHAR_a) && ib < (CHAR_a + 26))
		    sb.append((char) ('A' + ib - CHAR_a));
		else
		    sb.append("UNK:" + ib);
	    }
	    catch (MemoryAccessException e)
	    {
		continue;
	    }
	}
	
	return sb.toString();
    }
}