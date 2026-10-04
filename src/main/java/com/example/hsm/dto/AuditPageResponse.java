package com.example.hsm.dto;

import java.util.List;

/** Paginated audit log response. */
public record AuditPageResponse(int page, int size, long totalElements, List<AuditRecordDto> records) {}
