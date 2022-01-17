package bnStringTypes;

import java.util.ArrayList;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

public class BCCStringDataType extends AbstractBnStringDataType
{
    private static final ArrayList<Integer> terminators = new ArrayList<Integer>()
    {{
	add(0x80);
	add(0xC0);
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
	      "bcc-utf8.tbl",
	      terminators,
	      dtm);
    }

    @Override
    public DataType clone(DataTypeManager dtm)
    {
	if (dtm == getDataTypeManager())
	    return this;

	return new BCCStringDataType(dtm);
    }
}