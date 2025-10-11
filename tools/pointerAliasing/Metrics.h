#pragma once

// Metrics with verbosity control:
// - SummaryOnly (default): collect per-phase data, print only final summary.
// - Verbose: also print BEGIN/END live logs.
// - Silent: collect nothing and print nothing (cheap).

#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "llvm/Support/raw_ostream.h"

namespace psr::perf {

using Clock    = std::chrono::steady_clock;
using SysClock = std::chrono::system_clock;

struct PhaseResult {
  std::string   Name;
  double        Ms       = 0.0;
  std::uint64_t RSSStart = 0;
  std::uint64_t RSSEnd   = 0;
};

inline std::vector<PhaseResult> &phases() {
  static std::vector<PhaseResult> V;
  return V;
}

inline std::string wallNow() {
  const auto tp = SysClock::now();
  const auto t  = SysClock::to_time_t(tp);
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    tp.time_since_epoch()) % 1000;
  std::tm tm{};
#if defined(_WIN32)
  localtime_s(&tm, &t);
#else
  localtime_r(&t, &tm);
#endif
  std::ostringstream os;
  os << std::put_time(&tm, "%H:%M:%S") << '.'
     << std::setw(3) << std::setfill('0') << ms.count();
  return os.str();
}

inline std::uint64_t readProcStatusKB(const char *Key) {
  std::ifstream in("/proc/self/status");
  if (!in) return 0;
  std::string line, k(Key);
  while (std::getline(in, line)) {
    if (line.rfind(k, 0) == 0) {
      std::istringstream is(line.substr(k.size()));
      std::uint64_t kb = 0;
      is >> kb;
      return kb;
    }
  }
  return 0;
}

inline std::uint64_t rssBytes() { return readProcStatusKB("VmRSS:") * 1024ULL; }
inline std::uint64_t hwmBytes() { return readProcStatusKB("VmHWM:") * 1024ULL; }

inline std::string fmtBytes(std::uint64_t B) {
  static constexpr const char* U[] = {"B","KB","MB","GB","TB"};
  double d = static_cast<double>(B);
  int i = 0;
  while (d >= 1024.0 && i < 4) { d /= 1024.0; ++i; }
  std::ostringstream os;
  os << std::fixed
     << std::setprecision(d < 10 ? 2 : (d < 100 ? 1 : 0))
     << d << ' ' << U[i];
  return os.str();
}

inline std::string fmtMs(double ms) {
  std::ostringstream os;
  os.setf(std::ios::fixed);
  os << std::setprecision(3) << ms;
  return os.str();
}

// Adaptive time formatter for totals/summary lines.
inline std::string fmtAdaptiveTime(double ms) {
  double s = ms / 1000.0;
  std::ostringstream os;
  os.setf(std::ios::fixed);
  if (s < 1.0) {
    os << std::setprecision(3) << ms << " ms";
  } else if (s < 60.0) {
    os << std::setprecision(3) << s << " s";
  } else if (s < 3600.0) {
    os << std::setprecision(3) << (s / 60.0) << " min";
  } else {
    os << std::setprecision(3) << (s / 3600.0) << " h";
  }
  return os.str();
}

// ---------- Verbosity control ----------
enum class TimingVerbosity { Verbose = 1, SummaryOnly = 0, Silent = 2 };

inline TimingVerbosity &timingVerbosity() {
#if defined(PSR_PERF_DEFAULT_VERBOSE)
  static TimingVerbosity V =
      (PSR_PERF_DEFAULT_VERBOSE == 1) ? TimingVerbosity::Verbose :
      (PSR_PERF_DEFAULT_VERBOSE == 2) ? TimingVerbosity::Silent  :
                                        TimingVerbosity::SummaryOnly;
#else
  static TimingVerbosity V = TimingVerbosity::SummaryOnly; // default
#endif
  return V;
}

inline void setTimingVerbosity(TimingVerbosity V) { timingVerbosity() = V; }

inline bool liveLogsEnabled()   { return timingVerbosity() == TimingVerbosity::Verbose; }
inline bool summaryEnabled()    { return timingVerbosity() != TimingVerbosity::Silent; }
inline bool collectionEnabled() { return timingVerbosity() != TimingVerbosity::Silent; }

// ---------- Scoped phase ----------
struct ScopedPhase {
  std::string       Name;
  Clock::time_point T0;
  std::uint64_t     RSS0 = 0;

  explicit ScopedPhase(std::string N)
      : Name(std::move(N)),
        T0(Clock::now()),
        RSS0(collectionEnabled() ? rssBytes() : 0) {
    if (liveLogsEnabled()) {
      llvm::outs() << "[time] " << wallNow()
                   << "  BEGIN  " << Name
                   << "  rss="   << fmtBytes(RSS0) << "\n";
    }
  }

  ~ScopedPhase() {
    if (!collectionEnabled()) return;

    const auto t1   = Clock::now();
    const auto ms   = std::chrono::duration<double, std::milli>(t1 - T0).count();
    const auto rss1 = rssBytes();
    const auto dlt  = (rss1 > RSS0) ? (rss1 - RSS0) : 0;

    if (liveLogsEnabled()) {
      llvm::outs() << "[time] " << wallNow()
                   << "  END    " << Name
                   << "  elapsed=" << fmtMs(ms) << " ms"
                   << "  rss="     << fmtBytes(rss1)
                   << "  (Δ "      << fmtBytes(dlt) << ")\n";
    }

    phases().push_back(PhaseResult{ Name, ms, RSS0, rss1 });
  }

  ScopedPhase(const ScopedPhase&) = delete;
  ScopedPhase& operator=(const ScopedPhase&) = delete;
};

// ---------- Helpers for totals ----------
inline const PhaseResult* findPhase(std::string_view name) {
  for (const auto &R : phases()) {
    if (R.Name == name) return &R;
  }
  return nullptr;
}

inline void printTotals(std::string_view AnalysisLabel = {}) {
  if (!summaryEnabled()) return;

  // Overall
  if (const auto *Tot = findPhase("TOTAL")) {
    const auto rssDelta = (Tot->RSSEnd > Tot->RSSStart) ? (Tot->RSSEnd - Tot->RSSStart) : 0ULL;
    llvm::outs() << "\n[time] TOTAL: "
                 << fmtAdaptiveTime(Tot->Ms)
                 << " | rss start=" << fmtBytes(Tot->RSSStart)
                 << " end="         << fmtBytes(Tot->RSSEnd)
                 << " (Δ "          << fmtBytes(rssDelta) << ")"
                 << " | peak(HWM)=" << fmtBytes(hwmBytes())
                 << "\n";
  }

  // Per-analysis (if present)
  if (!AnalysisLabel.empty()) {
    std::string tag = std::string("ANALYSIS: ") + std::string(AnalysisLabel);
    if (const auto *A = findPhase(tag)) {
      const auto rssDelta = (A->RSSEnd > A->RSSStart) ? (A->RSSEnd - A->RSSStart) : 0ULL;
      llvm::outs() << "[time] " << tag << ": "
                   << fmtAdaptiveTime(A->Ms)
                   << " | rss start=" << fmtBytes(A->RSSStart)
                   << " end="         << fmtBytes(A->RSSEnd)
                   << " (Δ "          << fmtBytes(rssDelta) << ")"
                   << " | peak(HWM)=" << fmtBytes(hwmBytes())
                   << "\n";
    }
  }
}

// ---------- Summary ----------
inline void printPhaseSummary() {
  if (!summaryEnabled()) return;
  llvm::outs() << "\n[time] Phase summary:\n";
  for (const auto &R : phases()) {
    const auto rssDelta = (R.RSSEnd > R.RSSStart) ? (R.RSSEnd - R.RSSStart) : 0ULL;
    llvm::outs() << "  - " << R.Name << ": "
                 << fmtAdaptiveTime(R.Ms)
                 << " | rss start=" << fmtBytes(R.RSSStart)
                 << " end="         << fmtBytes(R.RSSEnd)
                 << " (Δ "          << fmtBytes(rssDelta) << ")"
                 << " | peak(HWM)=" << fmtBytes(hwmBytes())
                 << "\n";
  }
}

} // namespace psr::perf

// Convenience macro for unique variable names
#define PSR_PERF_SCOPED(name_literal) \
  ::psr::perf::ScopedPhase PSR_PERF_UNIQUE_VAR(__psr_perf_phase_){name_literal}
#define PSR_PERF_CONCAT(a,b) a##b
#define PSR_PERF_UNIQUE_VAR(base) PSR_PERF_CONCAT(base, __LINE__)
