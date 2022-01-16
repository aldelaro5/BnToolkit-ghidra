package bnStringTypes;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.data.StringLayoutEnum;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

// Abstract DataType that has custom logic for determining the length of the string
// and custom encoding scheme
public abstract class AbstractBnStringDataType extends AbstractStringDataType
{    
    private HashMap<Integer, String> characterMap = new HashMap<Integer, String>();
    private HashMap<String, Integer> reverseCharacterMap = new HashMap<String, Integer>();

    private int terminator = 0;
    
    public AbstractBnStringDataType(String name, String mnemonic, String defaultLabel,
		String defaultLabelPrefix, String defaultAbbrevLabelPrefix, String description,
		String tableFilePath, int terminator, DataTypeManager dtm)
    {
	super(name, mnemonic, defaultLabel, defaultLabelPrefix, defaultAbbrevLabelPrefix, description,
	      USE_CHARSET_DEF_DEFAULT, CharDataType.dataType, StringLayoutEnum.FIXED_LEN, dtm);
	
	this.terminator = terminator;
	
	if (characterMap.isEmpty() && reverseCharacterMap.isEmpty() && tableFilePath != null)
	    readTableFile(tableFilePath);
    }

    private void readTableFile(String filePath)
    {
	File file = new File(filePath);
	BufferedReader br = null;
	try
	{
	    br = new BufferedReader(new FileReader(file));
	    String line;
	    while ((line = br.readLine()) != null)
	    {
		String[] parts = line.split("=");
		if (parts.length != 2)
		    continue;
		
		int code = Integer.parseInt(parts[0], 16);
		// The codes are little endian hex string, but the parser assumed big endian
		// so we need to byte swap to get the correct code
		code = ((code & 0xff) << 8) | ((code & 0xff00) >> 8);
		String character = parts[1];
		
		characterMap.put(code, character);
		reverseCharacterMap.put(character, code);
	    }
	}
	catch (IOException e)
	{
	    e.printStackTrace();
	}
	finally
	{
	    try
	    {
		br.close();
	    }
	    catch (IOException e)
	    {
		e.printStackTrace();
	    }
	}
    }

    @Override
    public StringDataInstance getStringDataInstance(MemBuffer buf, Settings settings, int length) 
    {
	return new CustomStringDataInstance(this, settings, buf, length);
    }

    @Override
    public int getLength(MemBuffer buf, int maxLength)
    {
	for (int i = 0; i < Integer.MAX_VALUE; i++)
	{
	    try
	    {
		int ib = buf.getByte(i) & 0xFF;
		if (ib == terminator)
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
	    return ib != terminator;
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
		if (characterMap.containsKey(ib))
		    sb.append(characterMap.get(ib));
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