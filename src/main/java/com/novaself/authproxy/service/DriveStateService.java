package com.novaself.authproxy.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

@Service
public class DriveStateService {

    private static final Logger log = LoggerFactory.getLogger(DriveStateService.class);

    private static final String FILE_NAME = "novaself-state.json";
    private static final String DRIVE_FILES_URL = "https://www.googleapis.com/drive/v3/files";
    private static final String EMPTY_ENVELOPE = "{\"lastModified\":0,\"data\":{}}";

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    private final ObjectMapper mapper = new ObjectMapper();

    public record EnsureFileResult(String fileId, boolean created) {}
    private record CreateFileMetadata(String name, String mimeType) {}

    public EnsureFileResult ensureStateFile(String accessToken) throws Exception {
        String query = "name='" + FILE_NAME + "' and trashed=false and 'me' in owners";
        String url = DRIVE_FILES_URL + "?q=" + urlEncode(query) + "&fields=" + urlEncode("files(id)") + "&spaces=drive";

        JsonNode listing = get(url, accessToken);
        JsonNode files = listing.path("files");
        if (files.isArray() && files.size() > 0) {
            return new EnsureFileResult(files.get(0).path("id").asText(), false);
        }

        String metadataBody = mapper.writeValueAsString(new CreateFileMetadata(FILE_NAME, "application/json"));
        JsonNode created = postJson(DRIVE_FILES_URL, metadataBody, accessToken);
        String fileId = created.path("id").asText();

        patchMedia(fileId, EMPTY_ENVELOPE, accessToken);
        return new EnsureFileResult(fileId, true);
    }

    public String readState(String accessToken, String fileId) throws Exception {
        HttpResponse<String> response = http.send(
                authedRequest(DRIVE_FILES_URL + "/" + fileId + "?alt=media", accessToken).GET().build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() == 401) throw new GoogleAuthExpiredException();
        if (response.statusCode() >= 300) {
            log.error("[drive] read failed: HTTP {} body={}", response.statusCode(), response.body());
            throw new IllegalStateException("Drive read failed: HTTP " + response.statusCode() + " " + response.body());
        }
        String body = response.body();
        return (body == null || body.isBlank()) ? EMPTY_ENVELOPE : body;
    }

    public void writeState(String accessToken, String fileId, String jsonEnvelope) throws Exception {
        patchMedia(fileId, jsonEnvelope, accessToken);
    }

    private void patchMedia(String fileId, String content, String accessToken) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(DRIVE_FILES_URL + "/" + fileId + "?uploadType=media"))
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json; charset=UTF-8")
                .method("PATCH", HttpRequest.BodyPublishers.ofString(content, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 401) throw new GoogleAuthExpiredException();
        if (response.statusCode() >= 300) {
            log.error("[drive] write failed: HTTP {} body={}", response.statusCode(), response.body());
            throw new IllegalStateException("Drive write failed: HTTP " + response.statusCode() + " " + response.body());
        }
    }

    private JsonNode get(String url, String accessToken) throws Exception {
        HttpResponse<String> response = http.send(authedRequest(url, accessToken).GET().build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 401) throw new GoogleAuthExpiredException();
        if (response.statusCode() >= 300) {
            log.error("[drive] GET failed: HTTP {} body={}", response.statusCode(), response.body());
            throw new IllegalStateException("Drive GET failed: HTTP " + response.statusCode() + " " + response.body());
        }
        return mapper.readTree(response.body());
    }

    private JsonNode postJson(String url, String jsonBody, String accessToken) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json; charset=UTF-8")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 401) throw new GoogleAuthExpiredException();
        if (response.statusCode() >= 300) {
            log.error("[drive] POST failed: HTTP {} body={}", response.statusCode(), response.body());
            throw new IllegalStateException("Drive POST failed: HTTP " + response.statusCode() + " " + response.body());
        }
        return mapper.readTree(response.body());
    }

    private HttpRequest.Builder authedRequest(String url, String accessToken) {
        return HttpRequest.newBuilder().uri(URI.create(url)).header("Authorization", "Bearer " + accessToken);
    }

    private String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}