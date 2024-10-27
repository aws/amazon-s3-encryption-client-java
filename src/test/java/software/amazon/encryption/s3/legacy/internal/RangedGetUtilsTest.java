package software.amazon.encryption.s3.legacy.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

public class RangedGetUtilsTest {
    @Test
    public void testGetRangeWithValidRanges() {
        // Valid single and complete ranges
        assertArrayEquals(new long[]{10, Long.MAX_VALUE}, RangedGetUtils.getRange("bytes=10-"), "Start range should return expected output");
        assertArrayEquals(new long[]{10, 20}, RangedGetUtils.getRange("bytes=10-20"), "Complete range should return expected output");
        assertArrayEquals(new long[]{15, 15}, RangedGetUtils.getRange("bytes=15-15"), "Range with start equals end should return expected output");

        // Testing with Long.MAX_VALUE
        assertArrayEquals(new long[]{0, Long.MAX_VALUE}, RangedGetUtils.getRange("bytes=0-"));
        assertArrayEquals(new long[]{Long.MAX_VALUE - 1, Long.MAX_VALUE}, RangedGetUtils.getRange("bytes=" + (Long.MAX_VALUE - 1) + "-" + Long.MAX_VALUE));
    }

    @Test
    public void testGetRangeWithInvalidInputs() {
        // Null, empty, and invalid format inputs
        assertNull(RangedGetUtils.getRange(null), "Range should be null for null input");
        assertNull(RangedGetUtils.getRange(""), "Range should be null for empty input");
        assertNull(RangedGetUtils.getRange("bytes=abc"), "Range should be null for non-numeric input");
        assertNull(RangedGetUtils.getRange("10-100"), "Range should be null for missing 'bytes=' prefix");
        assertNull(RangedGetUtils.getRange("bytes=-"), "Range should be null for invalid range without start or end specified" );
        assertNull(RangedGetUtils.getRange("bytes=-10"), "Range should be null for invalid range with only end specified");
    }

    @Test
    public void testGetCryptoRangeWithInvalidRanges() {
        assertNull(RangedGetUtils.getCryptoRangeAsString("bytes=-100"), "Should return null for not specifying start range");
        assertNull(RangedGetUtils.getCryptoRangeAsString("bytes=100-10"), "Should return null for start greater than end range");
    }

    @Test
    public void testGetCryptoRangeAsStringAndAdjustmentWithValidRanges() {
        // Adjusted to include the full block that contains byte 0 and the full block after byte 15, given block size of 16
        assertEquals("bytes=0-32", RangedGetUtils.getCryptoRangeAsString("bytes=0-15"), "Should correctly adjust to full blocks for range as string");

        // Adjusted to include the full block before byte 10 and after byte 100 after adding offset
        assertEquals("bytes=0-128", RangedGetUtils.getCryptoRangeAsString("bytes=10-100"), "Should adjust range according to block size");

        // Edge case: Testing with Long.MAX_VALUE
        assertEquals("bytes=0-"+ Long.MAX_VALUE, RangedGetUtils.getCryptoRangeAsString("bytes=0-"));
        assertEquals("bytes=16-" + Long.MAX_VALUE, RangedGetUtils.getCryptoRangeAsString("bytes=40-" + Long.MAX_VALUE));
    }
}