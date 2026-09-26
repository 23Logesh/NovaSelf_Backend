package com.novaself.authproxy.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Java port of the merge strategy that used to live in the frontend's
 * googleSheets.ts. Now runs on the backend under a per-user lock, so two
 * devices saving "at the same time" can no longer race — the second save
 * always merges against the result of the first, atomically.
 */
@Service
public class StateMergeService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // Union by "id"; on a shared id, the LOCAL entry wins entirely.
    private static final List<String> UNION_BY_ID_FIELDS =
            List.of("intakes", "readingSessions", "chat", "dietPhases", "mess", "workoutPhases");

    public ObjectNode merge(ObjectNode local, ObjectNode remote) {
        ObjectNode result = MAPPER.createObjectNode();

        for (String field : UNION_BY_ID_FIELDS) {
            result.set(field, unionByKey(arrayOf(local, field), arrayOf(remote, field), "id"));
        }

        result.set("days", mergeDays(arrayOf(local, "days"), arrayOf(remote, "days")));
        result.set("skinLogs", unionByKey(arrayOf(local, "skinLogs"), arrayOf(remote, "skinLogs"), "date"));
        result.set("sleepLogs", unionByKey(arrayOf(local, "sleepLogs"), arrayOf(remote, "sleepLogs"), "date"));
        result.set("books", mergeBooks(arrayOf(local, "books"), arrayOf(remote, "books")));
        result.set("supplements", mergeSupplements(arrayOf(local, "supplements"), arrayOf(remote, "supplements")));

        mergeScalarByTimestamp(result, local, remote, "profile", "profileUpdatedAt");
        mergeScalarByTimestamp(result, local, remote, "settings", "settingsUpdatedAt");

        return result;
    }

    /** Union by key field; on a shared key, the LOCAL entry's fields win entirely. */
    private ArrayNode unionByKey(ArrayNode local, ArrayNode remote, String keyField) {
        Map<String, JsonNode> byKey = new LinkedHashMap<>();
        for (JsonNode n : remote) {
            String k = n.path(keyField).asText(null);
            if (k != null) byKey.put(k, n);
        }
        for (JsonNode n : local) {
            String k = n.path(keyField).asText(null);
            if (k != null) byKey.put(k, n);
        }
        ArrayNode out = MAPPER.createArrayNode();
        byKey.values().forEach(out::add);
        return out;
    }

    /** DayLog union by date. Shared date → union foods/water/workouts by id; weightKg prefers local. */
    private ArrayNode mergeDays(ArrayNode local, ArrayNode remote) {
        Map<String, ObjectNode> byDate = new LinkedHashMap<>();
        for (JsonNode n : remote) {
            String date = n.path("date").asText(null);
            if (date != null) byDate.put(date, (ObjectNode) n);
        }
        for (JsonNode n : local) {
            String date = n.path("date").asText(null);
            if (date == null) continue;
            ObjectNode localDay = (ObjectNode) n;
            ObjectNode remoteDay = byDate.get(date);
            if (remoteDay == null) {
                byDate.put(date, localDay);
                continue;
            }
            ObjectNode merged = MAPPER.createObjectNode();
            merged.put("date", date);
            JsonNode weightKg = localDay.has("weightKg") && !localDay.get("weightKg").isNull()
                    ? localDay.get("weightKg") : remoteDay.get("weightKg");
            if (weightKg != null) merged.set("weightKg", weightKg);
            merged.set("foods", unionByKey(arrayOf(localDay, "foods"), arrayOf(remoteDay, "foods"), "id"));
            merged.set("water", unionByKey(arrayOf(localDay, "water"), arrayOf(remoteDay, "water"), "id"));
            merged.set("workouts", unionByKey(arrayOf(localDay, "workouts"), arrayOf(remoteDay, "workouts"), "id"));
            byDate.put(date, merged);
        }
        ArrayNode out = MAPPER.createArrayNode();
        byDate.values().stream()
                .sorted((a, b) -> a.path("date").asText("").compareTo(b.path("date").asText("")))
                .forEach(out::add);
        return out;
    }

    /** Book union by id. Shared id → local wins metadata; pagesRead = max(local, remote); completed recomputed. */
    private ArrayNode mergeBooks(ArrayNode local, ArrayNode remote) {
        Map<String, ObjectNode> byId = new LinkedHashMap<>();
        for (JsonNode n : remote) {
            String id = n.path("id").asText(null);
            if (id != null) byId.put(id, (ObjectNode) n);
        }
        for (JsonNode n : local) {
            String id = n.path("id").asText(null);
            if (id == null) continue;
            ObjectNode localBook = (ObjectNode) n;
            ObjectNode remoteBook = byId.get(id);
            if (remoteBook == null) {
                byId.put(id, localBook);
                continue;
            }
            long pagesRead = Math.max(localBook.path("pagesRead").asLong(0), remoteBook.path("pagesRead").asLong(0));
            long totalPages = localBook.path("totalPages").asLong(0);
            ObjectNode merged = localBook.deepCopy();
            merged.put("pagesRead", pagesRead);
            merged.put("completed", pagesRead >= totalPages);
            byId.put(id, merged);
        }
        ArrayNode out = MAPPER.createArrayNode();
        byId.values().forEach(out::add);
        return out;
    }

    /** Supplement union by id. Shared id → local wins name/unit/defaultDose; stock = min(local, remote). */
    private ArrayNode mergeSupplements(ArrayNode local, ArrayNode remote) {
        Map<String, ObjectNode> byId = new LinkedHashMap<>();
        for (JsonNode n : remote) {
            String id = n.path("id").asText(null);
            if (id != null) byId.put(id, (ObjectNode) n);
        }
        for (JsonNode n : local) {
            String id = n.path("id").asText(null);
            if (id == null) continue;
            ObjectNode localSup = (ObjectNode) n;
            ObjectNode remoteSup = byId.get(id);
            if (remoteSup == null) {
                byId.put(id, localSup);
                continue;
            }
            double stock = Math.min(localSup.path("stock").asDouble(0), remoteSup.path("stock").asDouble(0));
            ObjectNode merged = localSup.deepCopy();
            merged.put("stock", stock);
            byId.put(id, merged);
        }
        ArrayNode out = MAPPER.createArrayNode();
        byId.values().forEach(out::add);
        return out;
    }

    /** Whichever side has the newer <field>UpdatedAt wins; a missing side always loses. */
    private void mergeScalarByTimestamp(ObjectNode result, ObjectNode local, ObjectNode remote,
                                          String valueField, String tsField) {
        boolean localHas = local.hasNonNull(valueField);
        boolean remoteHas = remote.hasNonNull(valueField);
        if (!localHas && !remoteHas) return;
        if (!remoteHas) { result.set(valueField, local.get(valueField)); result.put(tsField, local.path(tsField).asLong(0)); return; }
        if (!localHas) { result.set(valueField, remote.get(valueField)); result.put(tsField, remote.path(tsField).asLong(0)); return; }

        long localTs = local.path(tsField).asLong(0);
        long remoteTs = remote.path(tsField).asLong(0);
        if (localTs >= remoteTs) {
            result.set(valueField, local.get(valueField));
            result.put(tsField, localTs);
        } else {
            result.set(valueField, remote.get(valueField));
            result.put(tsField, remoteTs);
        }
    }

    private ArrayNode arrayOf(ObjectNode node, String field) {
        JsonNode v = node.path(field);
        return v.isArray() ? (ArrayNode) v : MAPPER.createArrayNode();
    }
}