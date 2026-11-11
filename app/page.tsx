"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import type { AuditReport } from "./api/audit/route";
import { useAuth } from "./context/AuthContext";
import Nav from "./nav";

import RemediationGuideModal from "./RemediationGuideModal";
import ScanHistoryDrawer from "./ScanHistoryDrawer";
import SecOpsAuthModal from "./SecOpsAuthModal";
import MainUI from "./MainUI";

const REMEDIATION_DB: Record<
  string,
  {
    name: string;
    desc: string;
    nginx: string;
    apache: string;
    cloudflare: string;
    nextjs: string;
    caddy: string;
  }
  > = {
    "Strict-Transport-Security": {
      name: "Strict-Transport-Security (HSTS)",
    desc: "Enforces browsers to exclusively access the domain over HTTPS for 1 year, including subdomains.",
    nginx: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
    apache: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
    cloudflare:
      "// In Cloudflare Dashboard -> SSL/TLS -> Edge Certificates -> Enable HSTS\n// Max-Age: 12 months, Include Subdomains: ON, Preload: ON",
    nextjs:
    '// next.config.js\nmodule.exports = {\n  async headers() {\n    return [{\n      source: "/:path*",\n      headers: [{ key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains; preload" }]\n    }];\n  }\n};',
    caddy: 'header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
  },
  "Content-Security-Policy": {
    name: "Content-Security-Policy (CSP)",
    desc: "Mitigates Cross-Site Scripting (XSS) and data injection by declaring approved content sources.",
    nginx:
      "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;\" always;",
    apache:
      "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self';\"",
    cloudflare:
      "// Add Transform Rule -> Modify Response Header\n// Header: Content-Security-Policy\n// Value: default-src 'self'; script-src 'self';",
    nextjs:
      '// next.config.js\nheaders: [{ key: "Content-Security-Policy", value: "default-src \'self\'; script-src \'self\';" }]',
    caddy: 'header Content-Security-Policy "default-src \'self\'; script-src \'self\';"',
  },
  "X-Frame-Options": {
    name: "X-Frame-Options",
    desc: "Defends against clickjacking by refusing iframe embedding across external origins.",
    nginx: 'add_header X-Frame-Options "SAMEORIGIN" always;',
    apache: 'Header always set X-Frame-Options "SAMEORIGIN"',
    cloudflare: "// Cloudflare Transform Rule -> Set X-Frame-Options to SAMEORIGIN",
    nextjs: 'headers: [{ key: "X-Frame-Options", value: "SAMEORIGIN" }]',
    caddy: 'header X-Frame-Options "SAMEORIGIN"',
  },
  "X-Content-Type-Options": {
    name: "X-Content-Type-Options",
    desc: "Prevents browser MIME-type sniffing vulnerabilities by enforcing declared MIME types.",
    nginx: 'add_header X-Content-Type-Options "nosniff" always;',
    apache: 'Header always set X-Content-Type-Options "nosniff"',
    cloudflare: "// Cloudflare Transform Rule -> Set X-Content-Type-Options to nosniff",
    nextjs: 'headers: [{ key: "X-Content-Type-Options", value: "nosniff" }]',
    caddy: 'header X-Content-Type-Options "nosniff"',
  },
  "Referrer-Policy": {
    name: "Referrer-Policy",
    desc: "Restricts referral info sent when following outbound hyperlinks, preventing sensitive URL leaks.",
    nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    apache: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    cloudflare:
      "// Cloudflare Transform Rule -> Set Referrer-Policy to strict-origin-when-cross-origin",
    nextjs:
      'headers: [{ key: "Referrer-Policy", value: "strict-origin-when-cross-origin" }]',
    caddy: 'header Referrer-Policy "strict-origin-when-cross-origin"',
  },
  "Permissions-Policy": {
    name: "Permissions-Policy",
    desc: "Restricts browser feature APIs such as camera, microphone, geolocation, and payment requests.",
    nginx:
      'add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;',
    apache:
      'Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"',
    cloudflare:
      "// Cloudflare Transform Rule -> Set Permissions-Policy to geolocation=(), camera=(), microphone=()",
    nextjs:
      'headers: [{ key: "Permissions-Policy", value: "geolocation=(), camera=(), microphone=()" }]',
    caddy:
      'header Permissions-Policy "geolocation=(), camera=(), microphone=()"',
  },
};

interface TerminalLog {
  id: string;
  ts: string;
  tag: string;
  msg: string;
}



export default function CyberShieldPage() {

  // Local States
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [isAudioMuted, setIsAudioMuted] = useState(false);
  const [targetInput, setTargetInput] = useState("");
  const [isAuditing, setIsAuditing] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  


// Authentication form state
const [authName, setAuthName] = useState("");
const [authEmail, setAuthEmail] = useState("");
const [authPassword, setAuthPassword] = useState("");

// Remediation copy state
const [remedCopied, setRemedCopied] = useState(false);


  // Live Terminal
  const [isTerminalVisible, setIsTerminalVisible] = useState(false);
  const [terminalLogs, setTerminalLogs] = useState<TerminalLog[]>([]);
  const [termStatus, setTermStatus] = useState<
    "IDLE" | "ACTIVE" | "RUNNING" | "FINISHED" | "FAILED"
  >("ACTIVE");

  // Results
  const [auditData, setAuditData] = useState<AuditReport | null>(null);
  const [animatedScore, setAnimatedScore] = useState(0);

  // Copy Buttons
  const [copyJsonText, setCopyJsonText] = useState("Copy JSON Report");
  const [copyMdText, setCopyMdText] = useState("Copy Executive Markdown");

  // Refs
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const cursorGlowRef = useRef<HTMLDivElement>(null);
  const cursorDotRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLDivElement>(null);

  // Shared Context States
  const {
    authModal,
    setAuthModal,

    isHistoryOpen,
    setIsHistoryOpen,

    scanHistory,
    setScanHistory,

    remedModal,
    setRemedModal,

    
    setIsProfileDropdownOpen,
    setUserProfile,
  } = useAuth();

  

  // Audio Engine
  const playSound = useCallback(
    (type: "click" | "scanStart" | "success" | "error") => {
      if (isAudioMuted) return;
      try {
        if (!audioCtxRef.current) {
          const AudioContextClass =
            window.AudioContext || (window as any).webkitAudioContext;
          if (AudioContextClass) audioCtxRef.current = new AudioContextClass();
        }
        const ctx = audioCtxRef.current;
        if (!ctx) return;
        if (ctx.state === "suspended") ctx.resume();

        const now = ctx.currentTime;
        if (type === "click") {
          const osc = ctx.createOscillator();
          const gain = ctx.createGain();
          osc.type = "sine";
          osc.frequency.setValueAtTime(800, now);
          osc.frequency.exponentialRampToValueAtTime(400, now + 0.04);
          gain.gain.setValueAtTime(0.04, now);
          gain.gain.linearRampToValueAtTime(0.001, now + 0.04);
          osc.connect(gain);
          gain.connect(ctx.destination);
          osc.start(now);
          osc.stop(now + 0.04);
        } else if (type === "scanStart") {
          const osc = ctx.createOscillator();
          const gain = ctx.createGain();
          osc.type = "triangle";
          osc.frequency.setValueAtTime(220, now);
          osc.frequency.exponentialRampToValueAtTime(880, now + 0.18);
          gain.gain.setValueAtTime(0.05, now);
          gain.gain.linearRampToValueAtTime(0.001, now + 0.2);
          osc.connect(gain);
          gain.connect(ctx.destination);
          osc.start(now);
          osc.stop(now + 0.2);
        } else if (type === "success") {
          [523.25, 659.25, 783.99].forEach((freq, idx) => {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = "sine";
            osc.frequency.setValueAtTime(freq, now + idx * 0.06);
            gain.gain.setValueAtTime(0.06, now + idx * 0.06);
            gain.gain.exponentialRampToValueAtTime(0.001, now + idx * 0.06 + 0.35);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now + idx * 0.06);
            osc.stop(now + idx * 0.06 + 0.35);
          });
        } else if (type === "error") {
          const osc = ctx.createOscillator();
          const gain = ctx.createGain();
          osc.type = "sawtooth";
          osc.frequency.setValueAtTime(180, now);
          osc.frequency.linearRampToValueAtTime(110, now + 0.22);
          gain.gain.setValueAtTime(0.08, now);
          gain.gain.linearRampToValueAtTime(0.001, now + 0.22);
          osc.connect(gain);
          gain.connect(ctx.destination);
          osc.start(now);
          osc.stop(now + 0.22);
        }
      } catch {}
    },
    [isAudioMuted]
  );

  // Initialize theme, audio, and history
  useEffect(() => {
    const savedTheme = (localStorage.getItem("cybershield-theme") as "dark" | "light") || "dark";
    setTheme(savedTheme);
    document.documentElement.setAttribute("data-theme", savedTheme);

    const savedAudio = localStorage.getItem("cybershield-audio-muted") === "true";
    setIsAudioMuted(savedAudio);

    try {
      const savedHistory = JSON.parse(localStorage.getItem("cybershield-history") || "[]");
      setScanHistory(savedHistory);
    } catch {}
  }, []);


  const toggleAudio = () => {
    const next = !isAudioMuted;
    setIsAudioMuted(next);
    localStorage.setItem("cybershield-audio-muted", String(next));
    if (!next) playSound("click");
  };

  // Particle Canvas & Cursor
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId: number;
    let mouseX = -300;
    let mouseY = -300;
    let smoothX = -300;
    let smoothY = -300;
    const sparks: Array<{
      x: number;
      y: number;
      vx: number;
      vy: number;
      radius: number;
      alpha: number;
      decay: number;
    }> = [];

    const handleResize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    handleResize();
    window.addEventListener("resize", handleResize);

    const handleMouseMove = (e: MouseEvent) => {
      mouseX = e.clientX;
      mouseY = e.clientY;
      if (cursorGlowRef.current) cursorGlowRef.current.style.opacity = "0.35";
      if (cursorDotRef.current) {
        cursorDotRef.current.style.left = `${mouseX}px`;
        cursorDotRef.current.style.top = `${mouseY}px`;
      }
      for (let i = 0; i < 2; i++) {
        sparks.push({
          x: mouseX,
          y: mouseY,
          vx: (Math.random() - 0.5) * 2,
          vy: (Math.random() - 0.5) * 2,
          radius: Math.random() * 2.8 + 1,
          alpha: 1,
          decay: Math.random() * 0.025 + 0.015,
        });
      }
    };

    const handleMouseLeave = () => {
      if (cursorGlowRef.current) cursorGlowRef.current.style.opacity = "0";
    };

    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("mouseleave", handleMouseLeave);

    const render = () => {
      smoothX += (mouseX - smoothX) * 0.14;
      smoothY += (mouseY - smoothY) * 0.14;
      if (cursorGlowRef.current) {
        cursorGlowRef.current.style.left = `${smoothX}px`;
        cursorGlowRef.current.style.top = `${smoothY}px`;
      }

      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const isDark = document.documentElement.getAttribute("data-theme") !== "light";
      const colorRgb = isDark ? "255, 106, 0" : "234, 88, 12";

      for (let i = sparks.length - 1; i >= 0; i--) {
        const s = sparks[i];
        s.x += s.vx;
        s.y += s.vy;
        s.alpha -= s.decay;
        s.radius *= 0.97;

        if (s.alpha <= 0 || s.radius <= 0.2) {
          sparks.splice(i, 1);
          continue;
        }

        ctx.beginPath();
        ctx.arc(s.x, s.y, s.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${colorRgb}, ${s.alpha * 0.7})`;
        ctx.fill();
      }

      animId = requestAnimationFrame(render);
    };
    render();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", handleResize);
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseleave", handleMouseLeave);
    };
  }, []);

  // Keyboard Shortcuts: Enter, Ctrl+K, H, Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        inputRef.current?.focus();
      } else if (
        e.key.toLowerCase() === "h" &&
        document.activeElement !== inputRef.current &&
        document.activeElement?.tagName !== "INPUT" &&
        document.activeElement?.tagName !== "TEXTAREA"
      ) {
        e.preventDefault();
        setIsHistoryOpen((prev) => !prev);
      } else if (e.key === "Escape") {
        setAuthModal((p) => ({ ...p, open: false }));
        setRemedModal((p) => ({ ...p, open: false }));
        setIsHistoryOpen(false);
        setIsProfileDropdownOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Score counter animation
  useEffect(() => {
    if (!auditData) return;
    setAnimatedScore(0);
    const target = auditData.score;
    const inc = Math.max(1, Math.ceil(target / 25));
    let curr = 0;
    const interval = setInterval(() => {
      curr += inc;
      if (curr >= target) {
        curr = target;
        clearInterval(interval);
      }
      setAnimatedScore(curr);
    }, 30);
    return () => clearInterval(interval);
  }, [auditData]);

  // Terminal scroll to bottom
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [terminalLogs]);

  const addLog = (tag: string, msg: string) => {
    const ts = new Date().toISOString().substring(14, 23);
    setTerminalLogs((prev) => [
      ...prev,
      { id: `${Date.now()}-${Math.random()}`, ts, tag, msg },
    ]);
  };

  const saveReportToHistory = (report: AuditReport) => {
    setScanHistory((prev) => {
      const filtered = prev.filter((h) => h.target !== report.target);
      const next = [report, ...filtered].slice(0, 25);
      try {
        localStorage.setItem("cybershield-history", JSON.stringify(next));
      } catch {}
      return next;
    });
  };

  const handleAudit = async (targetOverride?: string) => {
    const rawTarget = (targetOverride || targetInput).trim();
    if (!rawTarget) {
      setErrorMsg("Please enter a valid website hostname or URL (e.g. github.com)");
      playSound("error");
      return;
    }

    playSound("scanStart");
    setErrorMsg(null);
    setAuditData(null);
    setIsTerminalVisible(true);
    setTerminalLogs([]);
    setTermStatus("RUNNING");
    setIsAuditing(true);

    const now = new Date();
    const ts = now.toISOString().substring(14, 23);
    setTerminalLogs([
      { id: "1", ts, tag: "INIT", msg: `Auditing target: ${rawTarget}` },
      { id: "2", ts, tag: "DNS_LOOKUP", msg: "Resolving DNS record & socket connection..." },
    ]);

    const startTime = Date.now();
    const simulatedTelemetry = [
      { delay: 180, tag: "SOCKET_TCP", msg: "Connected to remote port 443 with TLS ALPN..." },
      { delay: 350, tag: "TLS_NEGOTIATE", msg: "Negotiating cipher suite & checking TLS 1.3 compliance..." },
      { delay: 550, tag: "X509_CHAIN", msg: "Extracting Certificate Authority, validity period & SANs..." },
      { delay: 750, tag: "HTTP_AUDIT", msg: "Scanning HSTS, CSP, Clickjacking & Referrer headers..." },
      { delay: 900, tag: "COOKIE_SEC", msg: "Auditing cookie security flags (Secure, HttpOnly, SameSite)..." },
    ];

    simulatedTelemetry.forEach((item) => {
      setTimeout(() => {
        setTermStatus((currentStatus) => {
          if (currentStatus === "RUNNING") {
            addLog(item.tag, item.msg);
          }
          return currentStatus;
        });
      }, item.delay);
    });

    try {
      const res = await fetch("/api/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: rawTarget }),
      });
      const data = await res.json();

      if (!res.ok || data.error) {
        throw new Error(data.error || "Failed to complete security audit.");
      }

      addLog(
        "SUCCESS",
        `Audit completed in ${Date.now() - startTime}ms. Threat Score: ${data.score}/100 [Grade ${data.grade}]`
      );
      setTermStatus("FINISHED");
      playSound("success");

      setTimeout(() => {
        setAuditData(data);
        saveReportToHistory(data);
        setIsAuditing(false);
      }, 500);
    } catch (err: any) {
      setTermStatus("FAILED");
      addLog("ERROR", err.message);
      playSound("error");
      setErrorMsg(err.message);
      setIsAuditing(false);
    }
  };

  const handleQuickPreset = (domain: string) => {
    playSound("click");
    setTargetInput(domain);
    handleAudit(domain);
  };

  const copyJson = () => {
    playSound("click");
    if (!auditData) return;
    navigator.clipboard.writeText(JSON.stringify(auditData, null, 2));
    setCopyJsonText("Copied!");
    setTimeout(() => setCopyJsonText("Copy JSON Report"), 2000);
  };

  const downloadJson = () => {
    playSound("click");
    if (!auditData) return;
    const blob = new Blob([JSON.stringify(auditData, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cybershield-${auditData.target}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyMarkdown = () => {
    playSound("click");
    if (!auditData) return;
    const d = auditData;
    const md = `# CyberShield Security Audit Report: ${d.target}
**Timestamp:** ${d.timestamp}
**Threat Intelligence Score:** ${d.score}/100 (Grade: ${d.grade})
**Posture Verdict:** ${d.verdict}

## Cryptographic Status
- **TLS Version:** ${d.tls.tls_version}
- **Cipher Suite:** ${d.tls.cipher_suite}
- **Certificate Issuer:** ${d.tls.issuer_org}
- **Cert Expiry:** ${d.tls.cert_expires_in_days} Days Remaining (${d.tls.expires_at})
- **HTTPS Redirect:** ${d.http.redirect_secure ? "Enforced" : "Missing"}
- **SHA-256 Fingerprint:** \`${d.tls.fingerprint_sha256}\`

## Missing Security Headers (Vulnerabilities)
${
  d.http.missing_headers
    .map((h) => `- [ ] **${h.name}** (${h.severity}): ${h.description}`)
    .join("\n") || "None - All headers enforced!"
}

## Enforced Headers
${Object.keys(d.http.present_headers || {})
  .map((k) => `- [x] **${k}**: \`${d.http.present_headers[k]}\``)
  .join("\n")}

*Generated by CyberShield Threat Intelligence Platform*`;

    navigator.clipboard.writeText(md);
    setCopyMdText("Copied Markdown!");
    setTimeout(() => setCopyMdText("Copy Executive Markdown"), 2000);
  };

  const openRemediation = (headerName: string) => {
    playSound("click");
    setRemedModal({
      open: true,
      header: headerName,
      tab: "nginx",
    });
    setRemedCopied(false);
  };

  const copyRemedSnippet = () => {
    playSound("click");
    const item = REMEDIATION_DB[remedModal.header];
    const snippet = item ? item[remedModal.tab] : `// Configuration for ${remedModal.header}`;
    navigator.clipboard.writeText(snippet);
    setRemedCopied(true);
    setTimeout(() => setRemedCopied(false), 2000);
  };

  const handleAuthSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    playSound("success");
    const name = authName.trim() || authEmail.split("@")[0] || "SecOps Analyst";

const initials = name
  .split(" ")
  .map((word) => word[0])
  .join("")
  .toUpperCase()
  .slice(0, 2);
    
    setUserProfile({ name, email: authEmail, initials });
    setAuthModal((p) => ({ ...p, open: false }));
  };


  const clearHistory = () => {
    playSound("click");
    if (confirm("Clear all local audit history?")) {
      setScanHistory([]);
      localStorage.removeItem("cybershield-history");
    }
  };

  // Gauge calculations
  const circumference = 2 * Math.PI * 60;
  const gaugeOffset = auditData
    ? circumference - (auditData.score / 100) * circumference
    : circumference;

  return (
    <>
      {/* ═══════════ AMBIENT CANVAS & CURSOR ═══════════ */}
      <div className="ambient-canvas" aria-hidden="true">
        <div className="gradient-flow" />
        <div className="cyber-grid" />
        <div className="pulse-orb pulse-orb-1" />
        <div className="pulse-orb pulse-orb-2" />
        <div className="pulse-orb pulse-orb-3" />
      </div>
      <div className="cursor-glow" id="cursorGlow" ref={cursorGlowRef} />
      <div className="cursor-dot" id="cursorDot" ref={cursorDotRef} />
      <canvas
        id="particleCanvas"
        ref={canvasRef}
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          width: "100%",
          height: "100%",
          pointerEvents: "none",
          zIndex: 9998,
        }}
      />

      {/* NAV... */}
      
         <Nav />

        {/* Main */}
        <MainUI/>

 


      {/* ═══════════ REMEDIATION GUIDE MODAL ═══════════ */}
      {remedModal.open && (
        <div
          className="modal-backdrop open"
          id="remedModal"
          onClick={() => setRemedModal((p) => ({ ...p, open: false }))}
        >
          <div
            className="modal-window ember-card"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              className="modal-close-btn"
              onClick={() => {
                playSound("click");
                setRemedModal((p) => ({ ...p, open: false }));
              }}
            >
              <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
            <h3
              id="remedHeaderName"
              style={{
                fontSize: "1.4rem",
                fontWeight: 800,
                marginBottom: "6px",
                color: "var(--text-primary)",
                fontFamily: "var(--font-heading)",
              }}
            >
              {REMEDIATION_DB[remedModal.header]?.name || remedModal.header}
            </h3>
            <p
              id="remedHeaderDesc"
              style={{
                color: "var(--text-muted)",
                fontSize: "0.88rem",
                marginBottom: "1.35rem",
                lineHeight: 1.5,
              }}
            >
              {REMEDIATION_DB[remedModal.header]?.desc || "Security header configuration directives."}
            </p>

            <div className="remed-tab-row">
              {(["nginx", "apache", "cloudflare", "nextjs", "caddy"] as const).map((tab) => (
                <button
                  key={tab}
                  className={`remed-tab-btn ${remedModal.tab === tab ? "active" : ""}`}
                  onClick={() => {
                    playSound("click");
                    setRemedModal((p) => ({ ...p, tab }));
                  }}
                >
                  {tab === "nextjs" ? "Next.js / Vercel" : tab.toUpperCase()}
                </button>
              ))}
            </div>

            <div className="code-box">
              <button className="code-copy-btn" id="remedCopyBtn" onClick={copyRemedSnippet}>
                {remedCopied ? "Copied!" : "Copy"}
              </button>
              <code id="remedCodeContent">
                {REMEDIATION_DB[remedModal.header]?.[remedModal.tab] ||
                  `// Add header ${remedModal.header} in server config`}
              </code>
            </div>
          </div>
        </div>
      )}

      {/* ═══════════ SCAN HISTORY DRAWER ═══════════ */}
      <ScanHistoryDrawer
  playSound={playSound}
  onSelectReport={setAuditData}
  onClearHistory={clearHistory}
/>


      {/* ═══════════ SECOPS AUTH MODAL ═══════════ */}
      {authModal.open && (
        <div
          className="modal-backdrop open"
          id="authModal"
          onClick={() => setAuthModal((p) => ({ ...p, open: false }))}
        >
          <div
            className="modal-window ember-card"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              className="modal-close-btn"
              onClick={() => {
                playSound("click");
                setAuthModal((p) => ({ ...p, open: false }));
              }}
            >
              <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
            <div style={{ textAlign: "center", marginBottom: "1rem" }}>
              <h3 style={{ fontSize: "1.5rem", fontWeight: 800, color: "var(--text-primary)", fontFamily: "var(--font-heading)" }}>
                SecOps Analyst Portal
              </h3>
              <p style={{ color: "var(--text-muted)", fontSize: "0.88rem" }}>
                Authenticate for elevated telemetry features
              </p>
            </div>

            <div className="auth-tab-row">
              <button
                className={`auth-tab-btn ${authModal.tab === "signin" ? "active" : ""}`}
                id="tabSignIn"
                onClick={() => {
                  playSound("click");
                  setAuthModal((p) => ({ ...p, tab: "signin" }));
                }}
              >
                Sign In
              </button>
              <button
                className={`auth-tab-btn ${authModal.tab === "signup" ? "active" : ""}`}
                id="tabSignUp"
                onClick={() => {
                  playSound("click");
                  setAuthModal((p) => ({ ...p, tab: "signup" }));
                }}
              >
                Create Account
              </button>
            </div>

            <form id="authForm" onSubmit={handleAuthSubmit}>
              {authModal.tab === "signup" && (
                <div className="auth-field" id="nameFieldGroup">
                  <label className="auth-label">Full Name</label>
                  <input
                    type="text"
                    id="authName"
                    className="auth-input-elem"
                    placeholder="Alex Morgan"
                    value={authName}
                    onChange={(e) => setAuthName(e.target.value)}
                  />
                </div>
              )}
              <div className="auth-field">
                <label className="auth-label">SecOps Email</label>
                <input
                  type="email"
                  id="authEmail"
                  className="auth-input-elem"
                  placeholder="analyst@cybershield.internal"
                  required
                  value={authEmail}
                  onChange={(e) => setAuthEmail(e.target.value)}
                />
              </div>
              <div className="auth-field">
                <label className="auth-label">Password</label>
                <input
                  type="password"
                  id="authPassword"
                  className="auth-input-elem"
                  placeholder="••••••••••••"
                  required
                  value={authPassword}
                  onChange={(e) => setAuthPassword(e.target.value)}
                />
              </div>
              <button type="submit" className="auth-submit-btn" id="authSubmitText">
                {authModal.tab === "signup" ? "Register SecOps Account" : "Access CyberShield Terminal"}
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
