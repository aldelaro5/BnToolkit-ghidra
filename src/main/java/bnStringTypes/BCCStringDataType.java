package bnStringTypes;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

public class BCCStringDataType extends AbstractBnStringDataType
{
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
	      "data/bcc-utf8.tbl",
	      0x80,
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