package com.trustguard.util;

import java.time.Instant;
import java.time.format.DateTimeFormatter;

public final class TimeUtils {

    private TimeUtils() {
    }

    public static String formatIso(Instant instant) {
        return instant == null ? null : DateTimeFormatter.ISO_INSTANT.format(instant);
    }

    public static Instant adjustForSourceOffset(Instant sourceEventTime, long sourceClockOffsetMs) {
        return sourceEventTime.minusMillis(sourceClockOffsetMs);
    }
}
