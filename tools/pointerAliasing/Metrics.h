#pragma once

#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
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

struct ScopedPhase {
  std::string       Name;
  Clock::time_point T0;
  std::uint64_t     RSS0 = 0;

  explicit ScopedPhase(std::string N)
      : Name(std::move(N)), T0(Clock::now()), RSS0(rssBytes()) {
    llvm::outs() << "[time] " << wallNow()
                 << "  BEGIN  " << Name
                 << "  rss="   << fmtBytes(RSS0) << "\n";
  }

  ~ScopedPhase() {
    const auto t1   = Clock::now();
    const auto ms   = std::chrono::duration<double, std::milli>(t1 - T0).count();
    const auto rss1 = rssBytes();
    const auto dlt  = (rss1 > RSS0) ? (rss1 - RSS0) : 0;

    llvm::outs() << "[time] " << wallNow()
                 << "  END    " << Name
                 << "  elapsed=" << fmtMs(ms) << " ms"
                 << "  rss="     << fmtBytes(rss1)
                 << "  (Δ "      << fmtBytes(dlt) << ")\n";

    phases().push_back(PhaseResult{ Name, ms, RSS0, rss1 });
  }

  ScopedPhase(const ScopedPhase&) = delete;
  ScopedPhase& operator=(const ScopedPhase&) = delete;
};

inline void printPhaseSummary() {
  llvm::outs() << "\n[time] Phase summary:\n";
  for (const auto &R : phases()) {
    llvm::outs() << "  - " << R.Name << ": "
                 << fmtMs(R.Ms) << " ms"
                 << " | rss start=" << fmtBytes(R.RSSStart)
                 << " end="         << fmtBytes(R.RSSEnd)
                 << " peak="        << fmtBytes(hwmBytes())
                 << "\n";
  }
}

} // namespace psr::perf

// Convenience macro for unique variable names
#define PSR_PERF_SCOPED(name_literal) \
  ::psr::perf::ScopedPhase PSR_PERF_UNIQUE_VAR(__psr_perf_phase_){name_literal}
#define PSR_PERF_CONCAT(a,b) a##b
#define PSR_PERF_UNIQUE_VAR(base) PSR_PERF_CONCAT(base, __LINE__)
