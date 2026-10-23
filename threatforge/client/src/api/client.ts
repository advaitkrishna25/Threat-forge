import { AnalysisRecord, AnalysisListResponse, StatsResponse } from "../types";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:3001";

export async function analyzeFile(file: File): Promise<AnalysisRecord> {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE}/api/analyze`, {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const errorJson = await response.json().catch(() => null);
    throw new Error(errorJson?.error || `Upload failed with status ${response.status}`);
  }

  return response.json();
}

export async function getAnalyses(params: {
  search?: string;
  verdict?: string;
  sort?: string;
  page?: number;
  limit?: number;
} = {}): Promise<AnalysisListResponse> {
  const query = new URLSearchParams();
  if (params.search) query.set("search", params.search);
  if (params.verdict && params.verdict !== "ALL") query.set("verdict", params.verdict);
  if (params.sort) query.set("sort", params.sort);
  if (params.page) query.set("page", params.page.toString());
  if (params.limit) query.set("limit", params.limit.toString());

  const response = await fetch(`${API_BASE}/api/analyses?${query.toString()}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch analyses: ${response.statusText}`);
  }
  return response.json();
}

export async function getAnalysisById(id: string): Promise<AnalysisRecord> {
  const response = await fetch(`${API_BASE}/api/analyses/${id}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch analysis ${id}`);
  }
  return response.json();
}

export async function deleteAnalysis(id: string): Promise<void> {
  const response = await fetch(`${API_BASE}/api/analyses/${id}`, {
    method: "DELETE",
  });
  if (!response.ok) {
    throw new Error(`Failed to delete analysis`);
  }
}

export async function clearAllAnalyses(): Promise<void> {
  const response = await fetch(`${API_BASE}/api/analyses`, {
    method: "DELETE",
  });
  if (!response.ok) {
    throw new Error(`Failed to clear analysis history`);
  }
}

export async function getStats(): Promise<StatsResponse> {
  const response = await fetch(`${API_BASE}/api/stats`);
  if (!response.ok) {
    throw new Error(`Failed to fetch statistics`);
  }
  return response.json();
}
