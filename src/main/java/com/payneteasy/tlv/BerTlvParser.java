package com.payneteasy.tlv;


import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class BerTlvParser {

	private static final BerTagFactory DEFAULT_TAG_FACTORY = new DefaultBerTagFactory();

	private final BerTagFactory tagFactory;
    private final IBerTlvLogger log;

    public BerTlvParser() {
        this(DEFAULT_TAG_FACTORY, EMPTY_LOGGER);
    }

    public BerTlvParser(IBerTlvLogger aLogger) {
    	this(DEFAULT_TAG_FACTORY, aLogger);
    }
    
    public BerTlvParser(BerTagFactory aTagFactory) {
    	this(aTagFactory, EMPTY_LOGGER);
    }
    
    public BerTlvParser(BerTagFactory aTagFactory, IBerTlvLogger aLogger) {
    	tagFactory = aTagFactory;
    	log = aLogger;
    }
    
    public BerTlv parseConstructed(byte[] aBuf) {
        return parseConstructed(aBuf, 0, aBuf.length);
    }

    public BerTlv parseConstructed(byte[] aBuf, int aOffset, int aLen) {
        ParseResult result =  parseWithResult(0, aBuf, aOffset, aLen);
        return result.tlv;
    }

    public BerTlvs parse(byte[] aBuf) {
        return parse(aBuf, 0, aBuf.length);
    }

    public BerTlvs parse(byte[] aBuf, int aOffset, int aLength) {
        if (aBuf == null) {
            throw new IllegalArgumentException("Buffer is null");
        }
        if (aOffset < 0 || aLength < 0 || aOffset + aLength > aBuf.length) {
            throw new IllegalArgumentException("Invalid offset or length");
        }
        
        List<BerTlv> list = new ArrayList<BerTlv>();
        int pos = aOffset;
        
        while (pos < aOffset + aLength) {
            ParseResult result = parseWithResult(0, aBuf, pos, aLength - (pos - aOffset));
            if (result == null) {
                break;
            }
            list.add(result.tlv);
            pos = result.offset;
        }
        
        return new BerTlvs(list);
    }

    private ParseResult parseWithResult(int aLevel, byte[] aBuf, int aOffset, int aLen) {
        if (aLen < 2) {
            return null;
        }
        
        String levelPadding = createLevelPadding(aLevel);
        if (log.isDebugEnabled()) {
            log.debug("{}parseWithResult(level={}, offset={}, len={}, buf={})", 
                levelPadding, aLevel, aOffset, aLen, 
                HexUtil.toFormattedHexString(aBuf, aOffset, aLen));
        }

        // tag
        int tagBytesCount = getTagBytesCount(aBuf, aOffset);
        BerTag tag = createTag(levelPadding, aBuf, aOffset, tagBytesCount);
        
        // length
        int lengthBytesCount = getLengthBytesCount(aBuf, aOffset + tagBytesCount);
        int valueLength = getDataLength(aBuf, aOffset + tagBytesCount);
        
        if (log.isDebugEnabled()) {
            log.debug("{}lenBytesCount = {}, len = {}, lenBuf = {}", 
                levelPadding, lengthBytesCount, valueLength, 
                HexUtil.toFormattedHexString(aBuf, aOffset + tagBytesCount, lengthBytesCount));
        }

        // value
        if (tag.isConstructed()) {
            ArrayList<BerTlv> list = new ArrayList<BerTlv>();
            addChildren(aLevel, aBuf, aOffset + tagBytesCount + lengthBytesCount, 
                levelPadding, lengthBytesCount, valueLength, list);
            int resultOffset = aOffset + tagBytesCount + lengthBytesCount + valueLength;
            return new ParseResult(new BerTlv(tag, list), resultOffset);
        } else {
            byte[] value = new byte[valueLength];
            System.arraycopy(aBuf, aOffset + tagBytesCount + lengthBytesCount, 
                value, 0, valueLength);
            int resultOffset = aOffset + tagBytesCount + lengthBytesCount + valueLength;
            return new ParseResult(new BerTlv(tag, value), resultOffset);
        }
    }

    private int getTagBytesCount(byte[] aBuf, int aOffset) {
        if ((aBuf[aOffset] & 0x1F) == 0x1F) {
            int len = 2;
            for (int i = aOffset + 1; i < aOffset + 10; i++) {
                if ((aBuf[i] & 0x80) != 0x80) {
                    break;
                }
                len++;
            }
            return len;
        }
        return 1;
    }

    private int getLengthBytesCount(byte[] aBuf, int aOffset) {
        int len = aBuf[aOffset] & 0xff;
        if ((len & 0x80) == 0x80) {
            return 1 + (len & 0x7f);
        }
        return 1;
    }

    private int getDataLength(byte[] aBuf, int aOffset) {
        int length = aBuf[aOffset] & 0xff;
        if ((length & 0x80) == 0x80) {
            int numberOfBytes = length & 0x7f;
            if (numberOfBytes > 3) {
                throw new IllegalStateException(
                    String.format("At position %d the len is more then 3 [%d]", 
                        aOffset, numberOfBytes));
            }
            length = 0;
            for (int i = aOffset + 1; i < aOffset + 1 + numberOfBytes; i++) {
                length = length * 0x100 + (aBuf[i] & 0xff);
            }
        }
        return length;
    }

    /**
     *
     * @param aLevel          level for debug
     * @param aBuf            buffer
     * @param aOffset         offset (first byte)
     * @param levelPadding    level padding (for debug)
     * @param aDataBytesCount data bytes count
     * @param valueLength     length
     * @param list            list to add
     */
    private void addChildren(int aLevel, byte[] aBuf, int aOffset, String levelPadding, int aDataBytesCount, int valueLength, ArrayList<BerTlv> list) {
        int startPosition = aOffset;
        int len = valueLength;
        while (startPosition < aOffset + valueLength) {
            ParseResult result = parseWithResult(aLevel + 1, aBuf, startPosition, len);
            list.add(result.tlv);
            startPosition = result.offset;
            len = (aOffset + valueLength) - startPosition;
            
            if (log.isDebugEnabled()) {
                log.debug("{}level {}: adding {} with offset {}, startPosition={}, aDataBytesCount={}, valueLength={}",
                    levelPadding, aLevel, result.tlv.getTag(), result.offset, 
                    startPosition, aDataBytesCount, valueLength);
            }
        }
    }

    private String createLevelPadding(int aLevel) {
        if(!log.isDebugEnabled()) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for(int i=0; i<aLevel*4; i++) {
            sb.append(' ');
        }
        return sb.toString();
    }

    private static class ParseResult {
        public ParseResult(BerTlv aTlv, int aOffset) {
            tlv = aTlv;
            offset = aOffset;
        }

        @Override
        public String toString() {
            return "ParseResult{" +
                    "tlv=" + tlv +
                    ", offset=" + offset +
                    '}';
        }

        private final BerTlv tlv;
        private final int offset;
    }


    private BerTag createTag(String levelPadding, byte[] aBuf, int aOffset, int aTagBytesCount) {
        if(log.isDebugEnabled()) {
            log.debug("{}Creating tag {}...", levelPadding, HexUtil.toFormattedHexString(aBuf, aOffset, aTagBytesCount));
        }
        return tagFactory.createTag(aBuf, aOffset, aTagBytesCount);
    }

    private static final IBerTlvLogger EMPTY_LOGGER = new IBerTlvLogger() {
        public boolean isDebugEnabled() {
            return false;
        }

        public void debug(String aFormat, Object... args) {
        }
    };


}