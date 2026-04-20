import { CATEGORY_LABELS } from './chunk-PTK2JL2Y.js';
import { useState, useCallback, useEffect } from 'react';
import { jsx, jsxs, Fragment } from 'react/jsx-runtime';

var NAV_ITEMS = [
  { id: "overview", label: "Overview", icon: "\u{1F4CA}" },
  { id: "incidents", label: "Incidents", icon: "\u26A1" },
  { id: "blocked-ips", label: "Blocked IPs", icon: "\u{1F6AB}" },
  { id: "reports", label: "AI Reports", icon: "\u{1F916}" },
  { id: "settings", label: "Settings", icon: "\u2699\uFE0F" }
];
function ShieldDashboard({ apiBase = "/api/shield" }) {
  const [activePage, setActivePage] = useState("overview");
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${apiBase}/stats`);
      if (res.ok) {
        setStats(await res.json());
      }
    } catch (err) {
      console.error("Failed to fetch stats:", err);
    } finally {
      setLoading(false);
    }
  }, [apiBase]);
  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 3e4);
    return () => clearInterval(interval);
  }, [fetchStats]);
  return /* @__PURE__ */ jsx("div", { className: "shield-dashboard", children: /* @__PURE__ */ jsxs("div", { className: "shield-layout", children: [
    /* @__PURE__ */ jsxs("aside", { className: "shield-sidebar", children: [
      /* @__PURE__ */ jsxs("div", { className: "shield-sidebar-header", children: [
        /* @__PURE__ */ jsxs("div", { className: "shield-sidebar-logo", children: [
          /* @__PURE__ */ jsx("span", { className: "logo-icon", children: "\u{1F6E1}\uFE0F" }),
          /* @__PURE__ */ jsx("span", { className: "shield-glitch", "data-text": "XPECTO", children: "XPECTO" })
        ] }),
        /* @__PURE__ */ jsx("div", { className: "shield-sidebar-version", children: "Shield v0.1.0 // IDPS" })
      ] }),
      /* @__PURE__ */ jsx("nav", { className: "shield-sidebar-nav", children: NAV_ITEMS.map((item) => /* @__PURE__ */ jsxs(
        "button",
        {
          className: `shield-nav-item ${activePage === item.id ? "active" : ""}`,
          onClick: () => setActivePage(item.id),
          children: [
            /* @__PURE__ */ jsx("span", { className: "nav-icon", children: item.icon }),
            item.label
          ]
        },
        item.id
      )) }),
      /* @__PURE__ */ jsx("div", { className: "shield-sidebar-footer", children: /* @__PURE__ */ jsxs("div", { style: { display: "flex", alignItems: "center", gap: "0.5rem" }, children: [
        /* @__PURE__ */ jsx("span", { className: "shield-status-dot shield-status-dot--active" }),
        /* @__PURE__ */ jsx("span", { style: {
          fontFamily: "var(--shield-font-accent)",
          fontSize: "0.6rem",
          textTransform: "uppercase",
          letterSpacing: "1.5px",
          color: "var(--shield-accent)"
        }, children: "Engine Active" })
      ] }) })
    ] }),
    /* @__PURE__ */ jsxs("main", { className: "shield-main", children: [
      activePage === "overview" && /* @__PURE__ */ jsx(OverviewPage, { stats, loading, apiBase }),
      activePage === "incidents" && /* @__PURE__ */ jsx(IncidentsPage, { apiBase }),
      activePage === "blocked-ips" && /* @__PURE__ */ jsx(BlockedIPsPage, { apiBase }),
      activePage === "reports" && /* @__PURE__ */ jsx(ReportsPage, { apiBase }),
      activePage === "settings" && /* @__PURE__ */ jsx(SettingsPage, { apiBase })
    ] })
  ] }) });
}
function OverviewPage({
  stats,
  loading,
  apiBase
}) {
  if (loading) return /* @__PURE__ */ jsx(LoadingState, {});
  if (!stats) return /* @__PURE__ */ jsx(EmptyState, { text: "No data available", icon: "\u{1F4ED}" });
  const categoryColors = {
    sqli: "#ff3366",
    xss: "#ff00ff",
    lfi: "#00d4ff",
    ssrf: "#ffaa00",
    "path-traversal": "#9966ff"
  };
  const maxCategoryCount = Math.max(
    ...Object.values(stats.categoryBreakdown),
    1
  );
  return /* @__PURE__ */ jsxs(Fragment, { children: [
    /* @__PURE__ */ jsxs("div", { className: "shield-page-header", children: [
      /* @__PURE__ */ jsx("h1", { className: "shield-page-title", children: /* @__PURE__ */ jsx("span", { className: "shield-glitch", "data-text": "DASHBOARD", children: "DASHBOARD" }) }),
      /* @__PURE__ */ jsx("p", { className: "shield-page-subtitle", children: "System Overview // Real-Time Threat Intelligence" })
    ] }),
    /* @__PURE__ */ jsxs("div", { className: "shield-stats-grid", children: [
      /* @__PURE__ */ jsxs("div", { className: "shield-stat-card", children: [
        /* @__PURE__ */ jsx("div", { className: "shield-stat-label", children: "Total Incidents" }),
        /* @__PURE__ */ jsx("div", { className: "shield-stat-value", children: formatNumber(stats.totalIncidents) })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "shield-stat-card", children: [
        /* @__PURE__ */ jsx("div", { className: "shield-stat-label", children: "Blocked IPs" }),
        /* @__PURE__ */ jsx("div", { className: "shield-stat-value shield-stat-value--danger", children: formatNumber(stats.totalBlockedIPs) })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "shield-stat-card", children: [
        /* @__PURE__ */ jsx("div", { className: "shield-stat-label", children: "Active Threats" }),
        /* @__PURE__ */ jsx("div", { className: `shield-stat-value ${stats.activeThreats > 0 ? "shield-stat-value--warning" : ""}`, children: stats.activeThreats })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "shield-stat-card", children: [
        /* @__PURE__ */ jsx("div", { className: "shield-stat-label", children: "Avg Confidence" }),
        /* @__PURE__ */ jsxs("div", { className: "shield-stat-value shield-stat-value--tertiary", children: [
          (stats.averageConfidence * 100).toFixed(1),
          "%"
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxs("div", { style: { display: "grid", gridTemplateColumns: "2fr 1fr", gap: "1rem", marginBottom: "2rem" }, children: [
      /* @__PURE__ */ jsxs("div", { className: "shield-chart", children: [
        /* @__PURE__ */ jsx("div", { className: "shield-chart-title", children: "Attack Timeline (24h)" }),
        /* @__PURE__ */ jsx("div", { className: "shield-bar-chart", children: stats.hourlyTimeline.length > 0 ? stats.hourlyTimeline.map((point, i) => {
          const maxCount = Math.max(...stats.hourlyTimeline.map((p) => p.count), 1);
          const height = point.count / maxCount * 100;
          return /* @__PURE__ */ jsx(
            "div",
            {
              className: "shield-bar",
              style: { height: `${Math.max(height, 2)}%` },
              title: `${point.hour}: ${point.count} attacks`
            },
            i
          );
        }) : /* @__PURE__ */ jsx(EmptyState, { text: "No timeline data", icon: "\u{1F4C8}" }) })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "shield-chart", children: [
        /* @__PURE__ */ jsx("div", { className: "shield-chart-title", children: "Attack Categories" }),
        /* @__PURE__ */ jsx("div", { className: "shield-category-bars", children: Object.entries(stats.categoryBreakdown).map(([cat, count]) => /* @__PURE__ */ jsxs("div", { className: "shield-category-bar", children: [
          /* @__PURE__ */ jsx("div", { className: "shield-category-bar-label", children: CATEGORY_LABELS[cat]?.split(" ")[0] || cat }),
          /* @__PURE__ */ jsx("div", { className: "shield-category-bar-track", children: /* @__PURE__ */ jsx(
            "div",
            {
              className: "shield-category-bar-fill",
              style: {
                width: `${count / maxCategoryCount * 100}%`,
                background: categoryColors[cat] || "#00ff88"
              }
            }
          ) }),
          /* @__PURE__ */ jsx("div", { className: "shield-category-bar-count", children: count })
        ] }, cat)) })
      ] })
    ] }),
    stats.topAttackerIPs.length > 0 && /* @__PURE__ */ jsxs("div", { className: "shield-chart", children: [
      /* @__PURE__ */ jsx("div", { className: "shield-chart-title", children: "Top Attacker IPs" }),
      /* @__PURE__ */ jsx("div", { className: "shield-table-wrapper", style: { clipPath: "none" }, children: /* @__PURE__ */ jsxs("table", { className: "shield-table", children: [
        /* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsxs("tr", { children: [
          /* @__PURE__ */ jsx("th", { children: "IP Address" }),
          /* @__PURE__ */ jsx("th", { children: "Attacks" }),
          /* @__PURE__ */ jsx("th", { children: "Last Category" })
        ] }) }),
        /* @__PURE__ */ jsx("tbody", { children: stats.topAttackerIPs.map((attacker, i) => /* @__PURE__ */ jsxs("tr", { children: [
          /* @__PURE__ */ jsx("td", { style: { fontFamily: "var(--shield-font-body)", color: "var(--shield-accent)" }, children: attacker.ip }),
          /* @__PURE__ */ jsx("td", { children: attacker.count }),
          /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx(CategoryBadge, { category: attacker.lastCategory }) })
        ] }, i)) })
      ] }) })
    ] })
  ] });
}
function IncidentsPage({ apiBase }) {
  const [incidents, setIncidents] = useState(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [categoryFilter, setCategoryFilter] = useState("");
  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: String(page), limit: "20" });
      if (categoryFilter) params.set("category", categoryFilter);
      const res = await fetch(`${apiBase}/incidents?${params}`);
      if (res.ok) setIncidents(await res.json());
    } catch (err) {
      console.error("Failed to fetch incidents:", err);
    } finally {
      setLoading(false);
    }
  }, [apiBase, page, categoryFilter]);
  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);
  return /* @__PURE__ */ jsxs(Fragment, { children: [
    /* @__PURE__ */ jsxs("div", { className: "shield-page-header", children: [
      /* @__PURE__ */ jsx("h1", { className: "shield-page-title", children: "Incidents" }),
      /* @__PURE__ */ jsx("p", { className: "shield-page-subtitle", children: "Detection Log // All Intercepted Threats" })
    ] }),
    /* @__PURE__ */ jsxs("div", { style: { display: "flex", gap: "0.75rem", marginBottom: "1.5rem", alignItems: "center" }, children: [
      /* @__PURE__ */ jsxs(
        "select",
        {
          className: "shield-select",
          style: { width: "200px" },
          value: categoryFilter,
          onChange: (e) => {
            setCategoryFilter(e.target.value);
            setPage(1);
          },
          children: [
            /* @__PURE__ */ jsx("option", { value: "", children: "All Categories" }),
            /* @__PURE__ */ jsx("option", { value: "sqli", children: "SQL Injection" }),
            /* @__PURE__ */ jsx("option", { value: "xss", children: "XSS" }),
            /* @__PURE__ */ jsx("option", { value: "lfi", children: "LFI" }),
            /* @__PURE__ */ jsx("option", { value: "ssrf", children: "SSRF" }),
            /* @__PURE__ */ jsx("option", { value: "path-traversal", children: "Path Traversal" })
          ]
        }
      ),
      /* @__PURE__ */ jsx("button", { className: "shield-btn shield-btn--ghost", onClick: () => fetchIncidents(), children: "\u21BB Refresh" })
    ] }),
    loading ? /* @__PURE__ */ jsx(LoadingState, {}) : !incidents || incidents.data.length === 0 ? /* @__PURE__ */ jsx(EmptyState, { text: "No incidents detected", icon: "\u2705" }) : /* @__PURE__ */ jsxs(Fragment, { children: [
      /* @__PURE__ */ jsx("div", { className: "shield-table-wrapper", children: /* @__PURE__ */ jsxs("table", { className: "shield-table", children: [
        /* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsxs("tr", { children: [
          /* @__PURE__ */ jsx("th", { children: "Timestamp" }),
          /* @__PURE__ */ jsx("th", { children: "Source IP" }),
          /* @__PURE__ */ jsx("th", { children: "Category" }),
          /* @__PURE__ */ jsx("th", { children: "Path" }),
          /* @__PURE__ */ jsx("th", { children: "Confidence" }),
          /* @__PURE__ */ jsx("th", { children: "Action" })
        ] }) }),
        /* @__PURE__ */ jsx("tbody", { children: incidents.data.map((inc, i) => /* @__PURE__ */ jsxs("tr", { children: [
          /* @__PURE__ */ jsx("td", { style: { whiteSpace: "nowrap", color: "var(--shield-muted-fg)", fontSize: "0.7rem" }, children: formatTimestamp(inc.timestamp) }),
          /* @__PURE__ */ jsx("td", { style: { fontFamily: "var(--shield-font-body)", color: "var(--shield-accent)" }, children: inc.sourceIP }),
          /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx(CategoryBadge, { category: inc.attackCategory }) }),
          /* @__PURE__ */ jsx("td", { style: { maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis" }, children: inc.requestPath }),
          /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx(ConfidenceBar, { value: inc.confidence }) }),
          /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("span", { className: `shield-badge shield-badge--${inc.action}`, children: inc.action }) })
        ] }, inc.id || i)) })
      ] }) }),
      /* @__PURE__ */ jsxs("div", { className: "shield-pagination", children: [
        /* @__PURE__ */ jsxs("div", { className: "shield-pagination-info", children: [
          "Page ",
          incidents.page,
          " of ",
          Math.ceil(incidents.total / incidents.limit),
          " // ",
          incidents.total,
          " total"
        ] }),
        /* @__PURE__ */ jsxs("div", { className: "shield-pagination-controls", children: [
          /* @__PURE__ */ jsx(
            "button",
            {
              className: "shield-btn shield-btn--ghost shield-btn--sm",
              disabled: page <= 1,
              onClick: () => setPage((p) => Math.max(1, p - 1)),
              children: "\u2190 Prev"
            }
          ),
          /* @__PURE__ */ jsx(
            "button",
            {
              className: "shield-btn shield-btn--ghost shield-btn--sm",
              disabled: !incidents.hasMore,
              onClick: () => setPage((p) => p + 1),
              children: "Next \u2192"
            }
          )
        ] })
      ] })
    ] })
  ] });
}
function BlockedIPsPage({ apiBase }) {
  const [blockedIPs, setBlockedIPs] = useState(null);
  const [loading, setLoading] = useState(true);
  const [blockInput, setBlockInput] = useState("");
  const fetchBlockedIPs = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${apiBase}/blocked-ips`);
      if (res.ok) setBlockedIPs(await res.json());
    } catch (err) {
      console.error("Failed to fetch blocked IPs:", err);
    } finally {
      setLoading(false);
    }
  }, [apiBase]);
  useEffect(() => {
    fetchBlockedIPs();
  }, [fetchBlockedIPs]);
  const handleBlock = async () => {
    if (!blockInput.trim()) return;
    try {
      await fetch(`${apiBase}/block-ip`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: blockInput.trim(), duration: 86400 })
      });
      setBlockInput("");
      fetchBlockedIPs();
    } catch (err) {
      console.error("Failed to block IP:", err);
    }
  };
  const handleUnblock = async (ip) => {
    try {
      await fetch(`${apiBase}/unblock-ip`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip })
      });
      fetchBlockedIPs();
    } catch (err) {
      console.error("Failed to unblock IP:", err);
    }
  };
  return /* @__PURE__ */ jsxs(Fragment, { children: [
    /* @__PURE__ */ jsxs("div", { className: "shield-page-header", children: [
      /* @__PURE__ */ jsx("h1", { className: "shield-page-title", children: "Blocked IPs" }),
      /* @__PURE__ */ jsx("p", { className: "shield-page-subtitle", children: "IP Blocklist Manager // Auto & Manual Blocks" })
    ] }),
    /* @__PURE__ */ jsxs("div", { style: { display: "flex", gap: "0.75rem", marginBottom: "1.5rem" }, children: [
      /* @__PURE__ */ jsxs("div", { className: "shield-input-wrapper", style: { flex: 1, maxWidth: "300px" }, children: [
        /* @__PURE__ */ jsx("span", { className: "shield-input-prefix", children: ">" }),
        /* @__PURE__ */ jsx(
          "input",
          {
            type: "text",
            className: "shield-input",
            placeholder: "Enter IP to block...",
            value: blockInput,
            onChange: (e) => setBlockInput(e.target.value),
            onKeyDown: (e) => e.key === "Enter" && handleBlock()
          }
        )
      ] }),
      /* @__PURE__ */ jsx("button", { className: "shield-btn shield-btn--danger", onClick: handleBlock, children: "Block IP" })
    ] }),
    loading ? /* @__PURE__ */ jsx(LoadingState, {}) : !blockedIPs || blockedIPs.data.length === 0 ? /* @__PURE__ */ jsx(EmptyState, { text: "No IPs currently blocked", icon: "\u{1F7E2}" }) : /* @__PURE__ */ jsx("div", { className: "shield-table-wrapper", children: /* @__PURE__ */ jsxs("table", { className: "shield-table", children: [
      /* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsxs("tr", { children: [
        /* @__PURE__ */ jsx("th", { children: "IP Address" }),
        /* @__PURE__ */ jsx("th", { children: "Reason" }),
        /* @__PURE__ */ jsx("th", { children: "Strikes" }),
        /* @__PURE__ */ jsx("th", { children: "Blocked At" }),
        /* @__PURE__ */ jsx("th", { children: "Expires" }),
        /* @__PURE__ */ jsx("th", { children: "Last Attack" }),
        /* @__PURE__ */ jsx("th", { children: "Actions" })
      ] }) }),
      /* @__PURE__ */ jsx("tbody", { children: blockedIPs.data.map((ip, i) => /* @__PURE__ */ jsxs("tr", { children: [
        /* @__PURE__ */ jsxs("td", { style: { fontFamily: "var(--shield-font-body)", color: "var(--shield-destructive)" }, children: [
          /* @__PURE__ */ jsx("span", { className: "shield-status-dot shield-status-dot--danger" }),
          ip.ipAddress
        ] }),
        /* @__PURE__ */ jsx("td", { children: ip.reason }),
        /* @__PURE__ */ jsx("td", { style: { color: "var(--shield-warning)" }, children: ip.strikeCount }),
        /* @__PURE__ */ jsx("td", { style: { fontSize: "0.7rem", color: "var(--shield-muted-fg)" }, children: formatTimestamp(ip.blockedAt) }),
        /* @__PURE__ */ jsx("td", { style: { fontSize: "0.7rem", color: "var(--shield-muted-fg)" }, children: ip.expiresAt ? formatTimestamp(ip.expiresAt) : "Permanent" }),
        /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx(CategoryBadge, { category: ip.lastAttackCategory }) }),
        /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx(
          "button",
          {
            className: "shield-btn shield-btn--ghost shield-btn--sm",
            onClick: () => handleUnblock(ip.ipAddress),
            children: "Unblock"
          }
        ) })
      ] }, ip.id || i)) })
    ] }) })
  ] });
}
function ReportsPage({ apiBase }) {
  const [reports, setReports] = useState(null);
  const [selectedReport, setSelectedReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const fetchReports = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${apiBase}/reports`);
      if (res.ok) setReports(await res.json());
    } catch (err) {
      console.error("Failed to fetch reports:", err);
    } finally {
      setLoading(false);
    }
  }, [apiBase]);
  useEffect(() => {
    fetchReports();
  }, [fetchReports]);
  const generateReport = async () => {
    setGenerating(true);
    try {
      const now = /* @__PURE__ */ new Date();
      const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1e3);
      const res = await fetch(`${apiBase}/generate-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          from: weekAgo.toISOString(),
          to: now.toISOString()
        })
      });
      if (res.ok) {
        const data = await res.json();
        setSelectedReport(data.report);
        fetchReports();
      }
    } catch (err) {
      console.error("Failed to generate report:", err);
    } finally {
      setGenerating(false);
    }
  };
  const viewReport = async (id) => {
    try {
      const res = await fetch(`${apiBase}/reports/${id}`);
      if (res.ok) setSelectedReport(await res.json());
    } catch (err) {
      console.error("Failed to fetch report:", err);
    }
  };
  return /* @__PURE__ */ jsxs(Fragment, { children: [
    /* @__PURE__ */ jsxs("div", { className: "shield-page-header", style: { display: "flex", justifyContent: "space-between", alignItems: "flex-start" }, children: [
      /* @__PURE__ */ jsxs("div", { children: [
        /* @__PURE__ */ jsx("h1", { className: "shield-page-title", children: "AI Reports" }),
        /* @__PURE__ */ jsx("p", { className: "shield-page-subtitle", children: "AI-Powered Security Analytics" })
      ] }),
      /* @__PURE__ */ jsx(
        "button",
        {
          className: "shield-btn shield-btn--secondary",
          onClick: generateReport,
          disabled: generating,
          children: generating ? "\u27F3 Generating..." : "\u{1F916} Generate Report"
        }
      )
    ] }),
    selectedReport ? /* @__PURE__ */ jsxs("div", { children: [
      /* @__PURE__ */ jsx(
        "button",
        {
          className: "shield-btn shield-btn--ghost",
          onClick: () => setSelectedReport(null),
          style: { marginBottom: "1rem" },
          children: "\u2190 Back to Reports"
        }
      ),
      /* @__PURE__ */ jsx(ReportDetail, { report: selectedReport })
    ] }) : loading ? /* @__PURE__ */ jsx(LoadingState, {}) : !reports || reports.data.length === 0 ? /* @__PURE__ */ jsx(EmptyState, { text: "No reports generated yet", icon: "\u{1F4CB}" }) : /* @__PURE__ */ jsx("div", { style: { display: "grid", gap: "1rem" }, children: reports.data.map((report, i) => /* @__PURE__ */ jsx(
      "div",
      {
        className: "shield-card shield-card--hoverable",
        style: { cursor: "pointer" },
        onClick: () => report.id && viewReport(report.id),
        children: /* @__PURE__ */ jsxs("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center" }, children: [
          /* @__PURE__ */ jsxs("div", { children: [
            /* @__PURE__ */ jsxs("div", { className: "shield-card-title", children: [
              "Report \u2014 ",
              formatTimestamp(report.createdAt)
            ] }),
            /* @__PURE__ */ jsxs("div", { style: { fontSize: "0.8rem", color: "var(--shield-fg)", marginBottom: "0.5rem" }, children: [
              report.executiveSummary.substring(0, 150),
              "..."
            ] }),
            /* @__PURE__ */ jsxs("div", { style: { display: "flex", gap: "0.75rem", fontSize: "0.7rem", color: "var(--shield-muted-fg)" }, children: [
              /* @__PURE__ */ jsxs("span", { children: [
                report.incidentCount,
                " incidents"
              ] }),
              /* @__PURE__ */ jsxs("span", { children: [
                "Model: ",
                report.modelUsed
              ] })
            ] })
          ] }),
          /* @__PURE__ */ jsx(ThreatLevelBadge, { level: report.threatLevel })
        ] })
      },
      report.id || i
    )) })
  ] });
}
function ReportDetail({ report }) {
  const parseJSON = (str) => {
    try {
      return JSON.parse(str);
    } catch {
      return null;
    }
  };
  const patterns = parseJSON(report.patternAnalysis);
  const trends = parseJSON(report.trendAnalysis);
  const risks = parseJSON(report.riskAssessment);
  const recommendations = parseJSON(report.recommendations);
  return /* @__PURE__ */ jsxs("div", { style: { display: "grid", gap: "1rem" }, children: [
    /* @__PURE__ */ jsxs("div", { className: "shield-card shield-card--holographic", children: [
      /* @__PURE__ */ jsxs("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }, children: [
        /* @__PURE__ */ jsx("div", { className: "shield-card-title", style: { marginBottom: 0 }, children: "AI Security Report" }),
        /* @__PURE__ */ jsx(ThreatLevelBadge, { level: report.threatLevel })
      ] }),
      /* @__PURE__ */ jsxs("div", { style: { fontSize: "0.7rem", color: "var(--shield-muted-fg)", display: "flex", gap: "1.5rem" }, children: [
        /* @__PURE__ */ jsxs("span", { children: [
          "\u{1F4C5} ",
          formatTimestamp(report.dateRangeStart),
          " \u2192 ",
          formatTimestamp(report.dateRangeEnd)
        ] }),
        /* @__PURE__ */ jsxs("span", { children: [
          "\u{1F4CA} ",
          report.incidentCount,
          " incidents"
        ] }),
        /* @__PURE__ */ jsxs("span", { children: [
          "\u{1F916} ",
          report.modelUsed
        ] })
      ] }),
      /* @__PURE__ */ jsx("div", { className: "shield-divider" }),
      /* @__PURE__ */ jsx("div", { style: { fontSize: "0.85rem", lineHeight: 1.7 }, children: report.executiveSummary })
    ] }),
    patterns && /* @__PURE__ */ jsxs("div", { className: "shield-card", children: [
      /* @__PURE__ */ jsx("div", { className: "shield-card-title", children: "Pattern Analysis" }),
      /* @__PURE__ */ jsx(ReportSection, { data: patterns })
    ] }),
    trends && /* @__PURE__ */ jsxs("div", { className: "shield-card", children: [
      /* @__PURE__ */ jsx("div", { className: "shield-card-title", children: "Trend Analysis" }),
      /* @__PURE__ */ jsx(ReportSection, { data: trends })
    ] }),
    risks && /* @__PURE__ */ jsxs("div", { className: "shield-card", children: [
      /* @__PURE__ */ jsx("div", { className: "shield-card-title", children: "Risk Assessment" }),
      /* @__PURE__ */ jsx(ReportSection, { data: risks })
    ] }),
    recommendations && /* @__PURE__ */ jsxs("div", { className: "shield-card", children: [
      /* @__PURE__ */ jsx("div", { className: "shield-card-title", children: "Recommendations" }),
      /* @__PURE__ */ jsx(ReportSection, { data: recommendations })
    ] })
  ] });
}
function ReportSection({ data }) {
  return /* @__PURE__ */ jsx("div", { style: { fontSize: "0.8rem", lineHeight: 1.7 }, children: Object.entries(data).map(([key, value]) => /* @__PURE__ */ jsxs("div", { style: { marginBottom: "0.75rem" }, children: [
    /* @__PURE__ */ jsx("div", { style: {
      fontFamily: "var(--shield-font-accent)",
      fontSize: "0.65rem",
      textTransform: "uppercase",
      letterSpacing: "1.5px",
      color: "var(--shield-accent)",
      marginBottom: "0.25rem"
    }, children: key.replace(/([A-Z])/g, " $1").trim() }),
    /* @__PURE__ */ jsx("div", { style: { color: "var(--shield-fg)" }, children: Array.isArray(value) ? value.map((item, i) => /* @__PURE__ */ jsxs("div", { style: { paddingLeft: "1rem", position: "relative" }, children: [
      /* @__PURE__ */ jsx("span", { style: { position: "absolute", left: 0, color: "var(--shield-accent)" }, children: "\u203A" }),
      String(item)
    ] }, i)) : typeof value === "object" && value !== null ? JSON.stringify(value, null, 2) : String(value) })
  ] }, key)) });
}
function SettingsPage({ apiBase }) {
  const [settings, setSettings] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [setupRunning, setSetupRunning] = useState(false);
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${apiBase}/settings`);
        if (res.ok) setSettings(await res.json());
      } catch (err) {
        console.error("Failed to fetch settings:", err);
      } finally {
        setLoading(false);
      }
    })();
  }, [apiBase]);
  const saveSettings = async () => {
    setSaving(true);
    try {
      await fetch(`${apiBase}/settings`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings)
      });
    } catch (err) {
      console.error("Failed to save settings:", err);
    } finally {
      setSaving(false);
    }
  };
  const runSetup = async () => {
    setSetupRunning(true);
    try {
      const res = await fetch(`${apiBase}/setup`, { method: "POST" });
      const data = await res.json();
      alert(data.message || "Setup complete!");
    } catch (err) {
      console.error("Setup failed:", err);
      alert("Setup failed. Check console for details.");
    } finally {
      setSetupRunning(false);
    }
  };
  if (loading) return /* @__PURE__ */ jsx(LoadingState, {});
  return /* @__PURE__ */ jsxs(Fragment, { children: [
    /* @__PURE__ */ jsxs("div", { className: "shield-page-header", children: [
      /* @__PURE__ */ jsx("h1", { className: "shield-page-title", children: "Settings" }),
      /* @__PURE__ */ jsx("p", { className: "shield-page-subtitle", children: "System Configuration // Appwrite & AI" })
    ] }),
    /* @__PURE__ */ jsxs("div", { style: { display: "grid", gap: "1rem", maxWidth: "600px" }, children: [
      /* @__PURE__ */ jsxs("div", { className: "shield-card", children: [
        /* @__PURE__ */ jsx("div", { className: "shield-card-title", children: "Database Setup" }),
        /* @__PURE__ */ jsx("p", { style: { fontSize: "0.8rem", color: "var(--shield-muted-fg)", marginBottom: "1rem" }, children: "Initialize or verify Appwrite collections, attributes, and indexes." }),
        /* @__PURE__ */ jsx(
          "button",
          {
            className: "shield-btn",
            onClick: runSetup,
            disabled: setupRunning,
            children: setupRunning ? "\u27F3 Running..." : "\u26A1 Run Setup"
          }
        )
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "shield-card", children: [
        /* @__PURE__ */ jsx("div", { className: "shield-card-title", children: "Engine Settings" }),
        /* @__PURE__ */ jsxs("div", { style: { display: "grid", gap: "1rem" }, children: [
          /* @__PURE__ */ jsx(
            SettingField,
            {
              label: "Confidence Threshold",
              value: settings["confidenceThreshold"] || "0.7",
              onChange: (v) => setSettings({ ...settings, confidenceThreshold: v })
            }
          ),
          /* @__PURE__ */ jsx(
            SettingField,
            {
              label: "Max Strikes",
              value: settings["maxStrikes"] || "3",
              onChange: (v) => setSettings({ ...settings, maxStrikes: v })
            }
          ),
          /* @__PURE__ */ jsx(
            SettingField,
            {
              label: "Block Duration (seconds)",
              value: settings["blockDuration"] || "86400",
              onChange: (v) => setSettings({ ...settings, blockDuration: v })
            }
          )
        ] })
      ] }),
      /* @__PURE__ */ jsx(
        "button",
        {
          className: "shield-btn shield-btn--filled",
          onClick: saveSettings,
          disabled: saving,
          style: { justifySelf: "start" },
          children: saving ? "\u27F3 Saving..." : "\u{1F4BE} Save Settings"
        }
      )
    ] })
  ] });
}
function SettingField({
  label,
  value,
  onChange
}) {
  return /* @__PURE__ */ jsxs("div", { children: [
    /* @__PURE__ */ jsx("label", { style: {
      display: "block",
      fontFamily: "var(--shield-font-accent)",
      fontSize: "0.65rem",
      textTransform: "uppercase",
      letterSpacing: "1.5px",
      color: "var(--shield-muted-fg)",
      marginBottom: "0.25rem"
    }, children: label }),
    /* @__PURE__ */ jsxs("div", { className: "shield-input-wrapper", children: [
      /* @__PURE__ */ jsx("span", { className: "shield-input-prefix", children: ">" }),
      /* @__PURE__ */ jsx(
        "input",
        {
          type: "text",
          className: "shield-input",
          value,
          onChange: (e) => onChange(e.target.value)
        }
      )
    ] })
  ] });
}
function CategoryBadge({ category }) {
  return /* @__PURE__ */ jsx("span", { className: `shield-badge shield-badge--${category}`, children: CATEGORY_LABELS[category] || category });
}
function ThreatLevelBadge({ level }) {
  return /* @__PURE__ */ jsx("span", { className: `shield-badge shield-badge--${level}`, children: level });
}
function ConfidenceBar({ value }) {
  const pct = value * 100;
  const color = pct >= 90 ? "var(--shield-destructive)" : pct >= 70 ? "var(--shield-warning)" : "var(--shield-accent)";
  return /* @__PURE__ */ jsxs("div", { style: { display: "flex", alignItems: "center", gap: "0.5rem" }, children: [
    /* @__PURE__ */ jsx("div", { style: {
      width: "60px",
      height: "4px",
      background: "var(--shield-muted)",
      overflow: "hidden"
    }, children: /* @__PURE__ */ jsx("div", { style: {
      width: `${pct}%`,
      height: "100%",
      background: color,
      transition: "width 300ms"
    } }) }),
    /* @__PURE__ */ jsxs("span", { style: { fontSize: "0.7rem", color, fontFamily: "var(--shield-font-body)" }, children: [
      pct.toFixed(0),
      "%"
    ] })
  ] });
}
function LoadingState() {
  return /* @__PURE__ */ jsx("div", { className: "shield-loading", children: /* @__PURE__ */ jsxs("div", { className: "shield-loading-dots", children: [
    /* @__PURE__ */ jsx("div", { className: "shield-loading-dot" }),
    /* @__PURE__ */ jsx("div", { className: "shield-loading-dot" }),
    /* @__PURE__ */ jsx("div", { className: "shield-loading-dot" })
  ] }) });
}
function EmptyState({ text, icon }) {
  return /* @__PURE__ */ jsxs("div", { className: "shield-empty", children: [
    /* @__PURE__ */ jsx("div", { className: "shield-empty-icon", children: icon }),
    /* @__PURE__ */ jsx("div", { className: "shield-empty-text", children: text })
  ] });
}
function formatNumber(n) {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return String(n);
}
function formatTimestamp(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false
    });
  } catch {
    return iso;
  }
}

export { ShieldDashboard };
//# sourceMappingURL=chunk-BLCETDRO.js.map
//# sourceMappingURL=chunk-BLCETDRO.js.map