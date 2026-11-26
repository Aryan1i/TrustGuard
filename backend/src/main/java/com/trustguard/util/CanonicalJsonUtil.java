package com.trustguard.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

public final class CanonicalJsonUtil {

    private static final ObjectMapper CANONICAL_MAPPER = JsonMapper.builder()
            .addModule(new JavaTimeModule())
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .build();

    private CanonicalJsonUtil() {
    }

    public static String toCanonicalJson(Object value) {
        try {
            return CANONICAL_MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize canonical JSON", e);
        }
    }

    public static ObjectMapper mapper() {
        return CANONICAL_MAPPER;
    }
}
