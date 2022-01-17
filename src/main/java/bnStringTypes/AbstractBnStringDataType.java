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
	
	// Disable this while I figure out how to properly load a file
	/*if (characterMap.isEmpty() && reverseCharacterMap.isEmpty() && tableFilePath != null)
	    readTableFile(tableFilePath);*/
	
	characterMap.put(0x0000, " ");
	characterMap.put(0x0100, "0");
	characterMap.put(0x0200, "1");
	characterMap.put(0x0300, "2");
	characterMap.put(0x0400, "3");
	characterMap.put(0x0500, "4");
	characterMap.put(0x0600, "5");
	characterMap.put(0x0700, "6");
	characterMap.put(0x0800, "7");
	characterMap.put(0x0900, "8");
	characterMap.put(0x0A00, "9");
	characterMap.put(0x0B00, "♠");
	characterMap.put(0x0C00, "♥");
	characterMap.put(0x0D00, "♦");
	characterMap.put(0x0E00, "♣");
	characterMap.put(0x0F00, "★");
	characterMap.put(0x1000, "カ");
	characterMap.put(0x1100, "キ");
	characterMap.put(0x1200, "ク");
	characterMap.put(0x1300, "ケ");
	characterMap.put(0x1400, "コ");
	characterMap.put(0x1500, "サ");
	characterMap.put(0x1600, "シ");
	characterMap.put(0x1700, "ス");
	characterMap.put(0x1800, "セ");
	characterMap.put(0x1900, "ソ");
	characterMap.put(0x1A00, "タ");
	characterMap.put(0x1B00, "チ");
	characterMap.put(0x1C00, "ツ");
	characterMap.put(0x1D00, "テ");
	characterMap.put(0x1E00, "ト");
	characterMap.put(0x1F00, "ナ");
	characterMap.put(0x2000, "ニ");
	characterMap.put(0x2100, "ヌ");
	characterMap.put(0x2200, "ネ");
	characterMap.put(0x2300, "ノ");
	characterMap.put(0x2400, "ハ");
	characterMap.put(0x2500, "ヒ");
	characterMap.put(0x2600, "フ");
	characterMap.put(0x2700, "ヘ");
	characterMap.put(0x2800, "ホ");
	characterMap.put(0x2900, "マ");
	characterMap.put(0x2A00, "ミ");
	characterMap.put(0x2B00, "ム");
	characterMap.put(0x2C00, "メ");
	characterMap.put(0x2D00, "モ");
	characterMap.put(0x2E00, "ヤ");
	characterMap.put(0x2F00, "ユ");
	characterMap.put(0x3000, "ヨ");
	characterMap.put(0x3100, "ラ");
	characterMap.put(0x3200, "リ");
	characterMap.put(0x3300, "ル");
	characterMap.put(0x3400, "レ");
	characterMap.put(0x3500, "ロ");
	characterMap.put(0x3600, "ワ");
	characterMap.put(0x3700, "[V2]");
	characterMap.put(0x3800, "[V3]");
	characterMap.put(0x3900, "ヲ");
	characterMap.put(0x3A00, "ン");
	characterMap.put(0x3B00, "ガ");
	characterMap.put(0x3C00, "ギ");
	characterMap.put(0x3D00, "グ");
	characterMap.put(0x3E00, "ゲ");
	characterMap.put(0x3F00, "ゴ");
	characterMap.put(0x4000, "ザ");
	characterMap.put(0x4100, "ジ");
	characterMap.put(0x4200, "ズ");
	characterMap.put(0x4300, "ゼ");
	characterMap.put(0x4400, "ゾ");
	characterMap.put(0x4500, "ダ");
	characterMap.put(0x4600, "ヂ");
	characterMap.put(0x4700, "ヅ");
	characterMap.put(0x4800, "デ");
	characterMap.put(0x4900, "ド");
	characterMap.put(0x4A00, "バ");
	characterMap.put(0x4B00, "ビ");
	characterMap.put(0x4C00, "ブ");
	characterMap.put(0x4D00, "ベ");
	characterMap.put(0x4E00, "ボ");
	characterMap.put(0x4F00, "パ");
	characterMap.put(0x5000, "ピ");
	characterMap.put(0x5100, "プ");
	characterMap.put(0x5200, "ペ");
	characterMap.put(0x5300, "ポ");
	characterMap.put(0x5400, "ァ");
	characterMap.put(0x5500, "ィ");
	characterMap.put(0x5600, "ゥ");
	characterMap.put(0x5700, "ェ");
	characterMap.put(0x5800, "ォ");
	characterMap.put(0x5900, "ッ");
	characterMap.put(0x5A00, "ャ");
	characterMap.put(0x5B00, "ュ");
	characterMap.put(0x5C00, "ョ");
	characterMap.put(0x5D00, "ヴ");
	characterMap.put(0x5E00, "A");
	characterMap.put(0x5F00, "B");
	characterMap.put(0x6000, "C");
	characterMap.put(0x6100, "D");
	characterMap.put(0x6200, "E");
	characterMap.put(0x6300, "F");
	characterMap.put(0x6400, "G");
	characterMap.put(0x6500, "H");
	characterMap.put(0x6600, "I");
	characterMap.put(0x6700, "J");
	characterMap.put(0x6800, "K");
	characterMap.put(0x6900, "L");
	characterMap.put(0x6A00, "M");
	characterMap.put(0x6B00, "N");
	characterMap.put(0x6C00, "O");
	characterMap.put(0x6D00, "P");
	characterMap.put(0x6E00, "Q");
	characterMap.put(0x6F00, "R");
	characterMap.put(0x7000, "S");
	characterMap.put(0x7100, "T");
	characterMap.put(0x7200, "U");
	characterMap.put(0x7300, "V");
	characterMap.put(0x7400, "W");
	characterMap.put(0x7500, "X");
	characterMap.put(0x7600, "Y");
	characterMap.put(0x7700, "Z");
	characterMap.put(0x7800, "-");
	characterMap.put(0x7900, "×");
	characterMap.put(0x7A00, "=");
	characterMap.put(0x7B00, ":");
	characterMap.put(0x7C00, "?");
	characterMap.put(0x7D00, "+");
	characterMap.put(0x7E00, "÷");
	characterMap.put(0x7F00, "※");
	characterMap.put(0x8000, "*");
	characterMap.put(0x8100, "!");
	characterMap.put(0x8200, "[$8200]");
	characterMap.put(0x8300, "%");
	characterMap.put(0x8400, "&");
	characterMap.put(0x8500, ",");
	characterMap.put(0x8600, "。");
	characterMap.put(0x8700, ".");
	characterMap.put(0x8800, "・");
	characterMap.put(0x8900, ";");
	characterMap.put(0x8A00, "'");
	characterMap.put(0x8B00, "\"");
	characterMap.put(0x8C00, "~");
	characterMap.put(0x8D00, "/");
	characterMap.put(0x8E00, "(");
	characterMap.put(0x8F00, ")");
	characterMap.put(0x9000, "「");
	characterMap.put(0x9100, "」");
	characterMap.put(0x9200, "↑");
	characterMap.put(0x9300, "→");
	characterMap.put(0x9400, "↓");
	characterMap.put(0x9500, "←");
	characterMap.put(0x9600, "@");
	characterMap.put(0x9700, "♥");
	characterMap.put(0x9800, "♪");
	characterMap.put(0x9900, "_");
	characterMap.put(0x9A00, "[");
	characterMap.put(0x9B00, "]");
	characterMap.put(0x9C00, "え");
	characterMap.put(0x9D00, "お");
	characterMap.put(0x9E00, "か");
	characterMap.put(0x9F00, "き");
	characterMap.put(0xA000, "く");
	characterMap.put(0xA100, "け");
	characterMap.put(0xA200, "こ");
	characterMap.put(0xA300, "さ");
	characterMap.put(0xA400, "し");
	characterMap.put(0xA500, "す");
	characterMap.put(0xA600, "せ");
	characterMap.put(0xA700, "そ");
	characterMap.put(0xA800, "た");
	characterMap.put(0xA900, "ち");
	characterMap.put(0xAA00, "つ");
	characterMap.put(0xAB00, "て");
	characterMap.put(0xAC00, "と");
	characterMap.put(0xAD00, "な");
	characterMap.put(0xAE00, "に");
	characterMap.put(0xAF00, "ぬ");
	characterMap.put(0xB000, "ね");
	characterMap.put(0xB100, "の");
	characterMap.put(0xB200, "は");
	characterMap.put(0xB300, "ひ");
	characterMap.put(0xB400, "ふ");
	characterMap.put(0xB500, "へ");
	characterMap.put(0xB600, "ほ");
	characterMap.put(0xB700, "ま");
	characterMap.put(0xB800, "み");
	characterMap.put(0xB900, "む");
	characterMap.put(0xBA00, "め");
	characterMap.put(0xBB00, "も");
	characterMap.put(0xBC00, "や");
	characterMap.put(0xBD00, "ゆ");
	characterMap.put(0xBE00, "よ");
	characterMap.put(0xBF00, "ら");
	characterMap.put(0xC000, "り");
	characterMap.put(0xC100, "る");
	characterMap.put(0xC200, "れ");
	characterMap.put(0xC300, "ろ");
	characterMap.put(0xC400, "わ");
	characterMap.put(0xC500, "ゐ");
	characterMap.put(0xC600, "ゑ");
	characterMap.put(0xC700, "を");
	characterMap.put(0xC800, "ん");
	characterMap.put(0xC900, "が");
	characterMap.put(0xCA00, "ぎ");
	characterMap.put(0xCB00, "ぐ");
	characterMap.put(0xCC00, "げ");
	characterMap.put(0xCD00, "ご");
	characterMap.put(0xCE00, "ざ");
	characterMap.put(0xCF00, "じ");
	characterMap.put(0xD000, "ず");
	characterMap.put(0xD100, "ぜ");
	characterMap.put(0xD200, "ぞ");
	characterMap.put(0xD300, "だ");
	characterMap.put(0xD400, "ぢ");
	characterMap.put(0xD500, "づ");
	characterMap.put(0xD600, "で");
	characterMap.put(0xD700, "ど");
	characterMap.put(0xD800, "ば");
	characterMap.put(0xD900, "び");
	characterMap.put(0xDA00, "ぶ");
	characterMap.put(0xDB00, "べ");
	characterMap.put(0xDC00, "ぼ");
	characterMap.put(0xDD00, "ぱ");
	characterMap.put(0xDE00, "ぴ");
	characterMap.put(0xDF00, "ぷ");
	characterMap.put(0xE000, "ぺ");
	characterMap.put(0xE100, "ぽ");
	characterMap.put(0xE200, "ぁ");
	characterMap.put(0xE300, "ぃ");
	characterMap.put(0xE400, "ぅ");
	characterMap.put(0xE500, "ぇ");
	characterMap.put(0xE600, "ぉ");
	characterMap.put(0xE700, "っ");
	characterMap.put(0xE800, "ゃ");
	characterMap.put(0xE900, "ゅ");
	characterMap.put(0xEA00, "ょ");
	characterMap.put(0xEB00, "a");
	characterMap.put(0xEC00, "b");
	characterMap.put(0xED00, "c");
	characterMap.put(0xEE00, "d");
	characterMap.put(0xEF00, "e");
	characterMap.put(0xF000, "f");
	characterMap.put(0xF100, "g");
	characterMap.put(0xF200, "h");
	characterMap.put(0xF300, "i");
	characterMap.put(0xF400, "j");
	characterMap.put(0xF500, "k");
	characterMap.put(0xF600, "l");
	characterMap.put(0xF700, "m");
	characterMap.put(0xF800, "n");
	characterMap.put(0xF900, "o");
	characterMap.put(0xFA00, "p");
	characterMap.put(0xFB00, "q");
	characterMap.put(0xFC00, "r");
	characterMap.put(0xFD00, "s");
	characterMap.put(0xFE00, "t");
	characterMap.put(0xFF00, "u");
	characterMap.put(0x0001, "v");
	characterMap.put(0x0101, "w");
	characterMap.put(0x0201, "x");
	characterMap.put(0x0301, "y");
	characterMap.put(0x0401, "z");
	characterMap.put(0x0501, "[$0501]");
	characterMap.put(0x0601, "[$0601]");
	characterMap.put(0x0701, "#");
	characterMap.put(0x0801, "ヱ");
	characterMap.put(0x0901, "ー");
	characterMap.put(0x0A01, "■");
	characterMap.put(0x0B01, "﹡");
	characterMap.put(0x0C01, "[V4]");
	characterMap.put(0x0D01, "[V5]");
	characterMap.put(0x0E01, "[equip1]");
	characterMap.put(0x0F01, "[equip2]");
	characterMap.put(0x1001, "[fadedot]");
	characterMap.put(0x2601, "[$2601]");
	characterMap.put(0x2701, "[$2701]");
	characterMap.put(0x2801, "[$2801]");
	characterMap.put(0x2901, "[$2901]");
	characterMap.put(0x2A01, "[$2A01]");
	characterMap.put(0x2B01, "[$2B01]");
	characterMap.put(0x2C01, "[$2C01]");
	characterMap.put(0x2D01, "[$2D01]");
	characterMap.put(0x2E01, "[$2E01]");
	characterMap.put(0x2F01, "[$2F01]");
	characterMap.put(0x3001, "[$3001]");
	characterMap.put(0x3101, "[$3101]");
	characterMap.put(0x3201, "[$3201]");
	characterMap.put(0x3301, "止");
	characterMap.put(0x3401, "彩");
	characterMap.put(0x3501, "起");
	characterMap.put(0x3601, "父");
	characterMap.put(0x3701, "博");
	characterMap.put(0x3801, "土");
	characterMap.put(0x3901, "一");
	characterMap.put(0x3A01, "二");
	characterMap.put(0x3B01, "三");
	characterMap.put(0x3C01, "四");
	characterMap.put(0x3D01, "五");
	characterMap.put(0x3E01, "六");
	characterMap.put(0x3F01, "七");
	characterMap.put(0x4001, "八");
	characterMap.put(0x4101, "九");
	characterMap.put(0x4201, "十");
	characterMap.put(0x4301, "百");
	characterMap.put(0x4401, "千");
	characterMap.put(0x4501, "万");
	characterMap.put(0x4601, "[$4601]");
	characterMap.put(0x4701, "上");
	characterMap.put(0x4801, "下");
	characterMap.put(0x4901, "左");
	characterMap.put(0x4A01, "右");
	characterMap.put(0x4B01, "手");
	characterMap.put(0x4C01, "足");
	characterMap.put(0x4D01, "日");
	characterMap.put(0x4E01, "目");
	characterMap.put(0x4F01, "月");
	characterMap.put(0x5001, "[$5001]");
	characterMap.put(0x5101, "[$5101]");
	characterMap.put(0x5201, "人");
	characterMap.put(0x5301, "入");
	characterMap.put(0x5401, "出");
	characterMap.put(0x5501, "山");
	characterMap.put(0x5601, "口");
	characterMap.put(0x5701, "光");
	characterMap.put(0x5801, "電");
	characterMap.put(0x5901, "気");
	characterMap.put(0x5A01, "話");
	characterMap.put(0x5B01, "広");
	characterMap.put(0x5C01, "[$5C01]");
	characterMap.put(0x5D01, "名");
	characterMap.put(0x5E01, "前");
	characterMap.put(0x5F01, "学");
	characterMap.put(0x6001, "校");
	characterMap.put(0x6301, "室");
	characterMap.put(0x6401, "世");
	characterMap.put(0x6501, "界");
	characterMap.put(0x6B01, "機");
	characterMap.put(0x6C01, "器");
	characterMap.put(0x6D01, "大");
	characterMap.put(0x6E01, "小");
	characterMap.put(0x6F01, "中");
	characterMap.put(0x7001, "自");
	characterMap.put(0x7101, "分");
	characterMap.put(0x7201, "間");
	characterMap.put(0x7501, "問");
	characterMap.put(0x7701, "門");
	characterMap.put(0x7801, "熱");
	characterMap.put(0x7901, "斗");
	characterMap.put(0x7A01, "要");
	characterMap.put(0x7C01, "道");
	characterMap.put(0x7D01, "行");
	characterMap.put(0x7E01, "街");
	characterMap.put(0x7F01, "屋");
	characterMap.put(0x8001, "水");
	characterMap.put(0x8101, "見");
	characterMap.put(0x8301, "教");
	characterMap.put(0x8401, "走");
	characterMap.put(0x8501, "先");
	characterMap.put(0x8601, "生");
	characterMap.put(0x8701, "長");
	characterMap.put(0x8801, "今");
	characterMap.put(0x8A01, "点");
	characterMap.put(0x8B01, "女");
	characterMap.put(0x8C01, "子");
	characterMap.put(0x8D01, "言");
	characterMap.put(0x8E01, "会");
	characterMap.put(0x8F01, "来");
	characterMap.put(0x9001, "[$9001]");
	characterMap.put(0x9101, "[$9101]");
	characterMap.put(0x9201, "[$9201]");
	characterMap.put(0x9301, "思");
	characterMap.put(0x9401, "時");
	characterMap.put(0x9501, "円");
	characterMap.put(0x9601, "知");
	characterMap.put(0x9701, "毎");
	characterMap.put(0x9801, "年");
	characterMap.put(0x9901, "火");
	characterMap.put(0x9A01, "朝");
	characterMap.put(0x9B01, "計");
	characterMap.put(0x9C01, "画");
	characterMap.put(0x9D01, "休");
	characterMap.put(0x9E01, "[$9E01]");
	characterMap.put(0x9F01, "[$9F01]");
	characterMap.put(0xA001, "回");
	characterMap.put(0xA101, "外");
	characterMap.put(0xA201, "多");
	characterMap.put(0xA401, "正");
	characterMap.put(0xA501, "死");
	characterMap.put(0xA601, "値");
	characterMap.put(0xA701, "合");
	characterMap.put(0xA801, "戦");
	characterMap.put(0xA901, "争");
	characterMap.put(0xAA01, "秋");
	characterMap.put(0xAB01, "原");
	characterMap.put(0xAC01, "町");
	characterMap.put(0xAD01, "天");
	characterMap.put(0xAE01, "用");
	characterMap.put(0xAF01, "金");
	characterMap.put(0xB001, "男");
	characterMap.put(0xB101, "作");
	characterMap.put(0xB201, "教");
	characterMap.put(0xB301, "方");
	characterMap.put(0xB401, "社");
	characterMap.put(0xB501, "攻");
	characterMap.put(0xB601, "撃");
	characterMap.put(0xB701, "カ");
	characterMap.put(0xB801, "同");
	characterMap.put(0xB901, "武");
	characterMap.put(0xBA01, "何");
	characterMap.put(0xBB01, "発");
	characterMap.put(0xBC01, "少");
	characterMap.put(0xBE01, "[$BE01]");
	characterMap.put(0xC001, "早");
	characterMap.put(0xC101, "暮");
	characterMap.put(0xC201, "面");
	characterMap.put(0xC301, "組");
	characterMap.put(0xC401, "後");
	characterMap.put(0xC501, "文");
	characterMap.put(0xC601, "字");
	characterMap.put(0xC701, "本");
	characterMap.put(0xC801, "階");
	characterMap.put(0xC901, "岩");
	characterMap.put(0xCA01, "才");
	characterMap.put(0xCB01, "者");
	characterMap.put(0xCC01, "立");
	characterMap.put(0xCE01, "[$CE01]");
	characterMap.put(0xCF01, "ヶ");
	characterMap.put(0xD001, "連");
	characterMap.put(0xD101, "射");
	characterMap.put(0xD201, "国");
	characterMap.put(0xD401, "耳");
	characterMap.put(0xD501, "土");
	characterMap.put(0xD601, "炎");
	characterMap.put(0xD701, "伊");
	characterMap.put(0xD801, "集");
	characterMap.put(0xD901, "院");
	characterMap.put(0xDA01, "各");
	characterMap.put(0xDB01, "科");
	characterMap.put(0xDC01, "省");
	characterMap.put(0xDD01, "祐");
	characterMap.put(0xDE01, "朗");
	characterMap.put(0xDF01, "枚");
	characterMap.put(0xE101, "川");
	characterMap.put(0xE201, "花");
	characterMap.put(0xE301, "兄");
	characterMap.put(0xE501, "音");
	characterMap.put(0xE601, "属");
	characterMap.put(0xE701, "性");
	characterMap.put(0xE801, "持");
	characterMap.put(0xE901, "勝");
	characterMap.put(0xEA01, "赤");
	characterMap.put(0xEB01, "[$EB01]");
	characterMap.put(0xEC01, "[$EC01]");
	characterMap.put(0xED01, "[$ED01]");
	characterMap.put(0xEE01, "丁");
	characterMap.put(0xF001, "地");
	characterMap.put(0xF101, "所");
	characterMap.put(0xF201, "明");
	characterMap.put(0xF301, "切");
	characterMap.put(0xF401, "急");
	characterMap.put(0xF501, "木");
	characterMap.put(0xF601, "無");
	characterMap.put(0xF701, "高");
	characterMap.put(0xF801, "駅");
	characterMap.put(0xF901, "店");
	characterMap.put(0xFC01, "[$FC01]");
	characterMap.put(0xFD01, "研");
	characterMap.put(0xFE01, "究");
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
	    br.close();
	}
	catch (IOException e)
	{
	    e.printStackTrace();
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
		//TODO: remove this when I figure out how files work
		ib = ((ib & 0xFF) << 8) | ((ib & 0xFF00) >> 8);
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