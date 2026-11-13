// SPDX-License-Identifier: AGPL-3.0-or-later
// omp-watch.cs - the smb-job-channel watchdog, without Windows PowerShell.
//
// Why this exists: the 1.0.0 watchdog published its state with a hidden
// `powershell -ExecutionPolicy Bypass -Command` child. Endpoint security (Huorong 企业版,
// 系统加固: 利用 PowerShell 执行可疑脚本) blocks that launch, so the mirror froze and the
// prompt even stalled the watchdog loop. 1.1.0 dropped the publish; this build goes one step
// further and removes powershell from the supervision path entirely: a scheduled task or the
// cmd :loop starts THIS exe, it decides from local files only (state\hb.json), kills a body
// that stopped beating, and starts the launcher with CreateNoWindow (no console, no script).
//
// Semantics are the 1.1.0 decision table:
//   body pid gone                          -> start the launcher
//   beacon age > stale, no job             -> kill tree, launcher restarts it (stale-idle)
//   beacon age > stale + grace, job in it  -> kill tree (stuck-job)
//   no beacon but pid alive                -> no-beacon -> kill
//   otherwise                              -> healthy, touch nothing
//
// Build (no SDK needed):
//   csc.exe /target:exe /platform:anycpu /optimize+ /out:omp-watch.exe omp-watch.cs
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

static class OmpWatch
{
    const string Version = "1.1.0-exe";

    static string _dir;
    static string _hb, _stats, _log, _lockFile, _bodyLock, _launcher;
    static string _bodyName = "omp-body.ps1";
    static string _launcherName = "start-bridge.cmd";
    static int _staleSec = 120, _graceSec = 120, _intervalSec = 30, _maxRestarts = 12;
    static bool _once, _quiet, _verbose;

    static int Main(string[] argv)
    {
        try
        {
            if (!ParseArgs(argv)) { Console.Error.WriteLine("usage: omp-watch.exe --dir <install> [--stale 120] [--grace 120] [--interval 30] [--once] [--quiet]"); return 2; }
            if (!Directory.Exists(_dir)) { Console.Error.WriteLine("no such install dir: " + _dir); return 2; }
            _hb = Path.Combine(_dir, @"state\hb.json");
            _stats = Path.Combine(_dir, @"state\watch.json");
            _log = Path.Combine(_dir, "watch.log");
            _lockFile = Path.Combine(_dir, "watch.lock");
            _bodyLock = Path.Combine(_dir, "bridge.lock");
            ReadSettings();
            _launcher = Path.Combine(_dir, _launcherName);

            FileStream lockStream;
            try { lockStream = new FileStream(_lockFile, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException)
            {
                Log("watchdog already running - nothing to do");
                return 0;
            }
            using (lockStream)
            {
                lockStream.SetLength(0);
                byte[] pidBytes = Encoding.UTF8.GetBytes(Process.GetCurrentProcess().Id + " " + DateTime.Now.ToString("s"));
                lockStream.Write(pidBytes, 0, pidBytes.Length);
                lockStream.Flush();

                Log("watchdog v" + Version + " up pid=" + Process.GetCurrentProcess().Id +
                    " dir=" + _dir + " stale=" + _staleSec + "s interval=" + _intervalSec + "s once=" + _once);

                if (_once) { Pass(); return 0; }
                while (true)
                {
                    Thread.Sleep(_intervalSec * 1000);
                    try { Pass(); }
                    catch (Exception ex) { Log("pass failed: " + ex.Message); }
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("fatal: " + ex);
            return 1;
        }
    }

    static bool ParseArgs(string[] a)
    {
        for (int i = 0; i < a.Length; i++)
        {
            switch (a[i].ToLowerInvariant())
            {
                case "--dir": if (++i >= a.Length) return false; _dir = a[i]; break;
                case "--stale": if (++i >= a.Length) return false; _staleSec = int.Parse(a[i]); break;
                case "--grace": if (++i >= a.Length) return false; _graceSec = int.Parse(a[i]); break;
                case "--interval": if (++i >= a.Length) return false; _intervalSec = int.Parse(a[i]); break;
                case "--max-restarts": if (++i >= a.Length) return false; _maxRestarts = int.Parse(a[i]); break;
                case "--once": _once = true; break;
                case "--quiet": _quiet = true; break;
                case "--verbose": _verbose = true; break;
                default: return false;
            }
        }
        if (string.IsNullOrEmpty(_dir)) _dir = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);
        return !string.IsNullOrEmpty(_dir);
    }

    static void ReadSettings()
    {
        string ini = Path.Combine(_dir, "settings.ini");
        if (!File.Exists(ini)) return;
        foreach (string raw in File.ReadAllLines(ini))
        {
            string line = raw.Trim();
            int eq = line.IndexOf('=');
            if (eq <= 0) continue;
            string k = line.Substring(0, eq).Trim().ToUpperInvariant();
            string v = line.Substring(eq + 1).Trim();
            if (k == "BODY_NAME" && v.Length > 0) _bodyName = v;
            if (k == "LAUNCHER_NAME" && v.Length > 0) _launcherName = v;
        }
    }

    // ---------------------------------------------------------------- one pass
    static void Pass()
    {
        string hbText = ReadAll(_hb);
        long bodyPid = Num(hbText, "pid");
        long hbTs = Num(hbText, "ts");
        string phase = Str(hbText, "phase");
        string jobId = Str(hbText, "job_id");
        string jobKind = Str(hbText, "job_kind");
        long now = Unix();
        long age = hbTs > 0 ? now - hbTs : -1;
        bool inJob = jobId.Length > 0;
        string jobDesc = inJob ? jobId + "/" + jobKind : "";

        bool bodyAlive = bodyPid > 0 && Alive((int)bodyPid);
        int launcherPid = LauncherPid();

        bool healthy = true;
        string reason = "";
        if (!File.Exists(_hb))
        {
            if (bodyAlive) { healthy = false; reason = "no-beacon"; }
            else if (launcherPid == 0) { healthy = false; reason = "no-body"; }
        }
        else if (!bodyAlive) { healthy = false; reason = "body-gone"; }
        else if (age > _staleSec + (inJob ? _graceSec : 0)) { healthy = false; reason = inJob ? "stuck-job" : "stale-idle"; }

        Dictionary<string, string> stats = ReadStats();
        int restarts = IntOr(Get(stats, "restarts"), 0);
        List<long> stamps = Stamps(Get(stats, "restart_stamps"));
        int recent = 0;
        foreach (long s in stamps) if (now - s < 3600) recent++;

        string lastReason = reason.Length > 0 ? reason : Get(stats, "last_reason");
        string lastRestart = Get(stats, "last_restart_at");
        string lastOk = Get(stats, "last_ok");

        if (!healthy && recent < _maxRestarts)
        {
            Log("RESTART reason=" + reason + " target_pid=" + bodyPid + " age=" + age + "s");
            KillTree(bodyPid);
            ReleaseLock(bodyPid);
            if (LauncherPid() == 0) StartLauncher(); else Log("launcher alive - it will respawn the body within ~20s");
            restarts++;
            lastReason = reason;
            lastRestart = DateTime.Now.ToString("s");
            stamps.Add(now);
        }
        else if (!healthy)
        {
            Log("unhealthy (" + reason + ") but restart budget used up - backing off");
            lastReason = "restart-budget-exhausted";
        }
        else
        {
            lastOk = DateTime.Now.ToString("s");
            if (_verbose && !_quiet) Console.WriteLine("ok body=" + bodyPid + " phase=" + phase + " age=" + age + "s");
        }

        StringBuilder stampsJson = new StringBuilder();
        List<long> keep = new List<long>();
        foreach (long s in stamps) if (now - s < 3600) keep.Add(s);
        for (int i = 0; i < keep.Count; i++) { if (i > 0) stampsJson.Append(","); stampsJson.Append(keep[i]); }

        StringBuilder sb = new StringBuilder();
        sb.Append("{");
        sb.Append("\"pid\":" + Process.GetCurrentProcess().Id + ",");
        sb.Append("\"version\":\"" + Version + "\",");
        sb.Append("\"host\":\"exe\",");
        sb.Append("\"stale_sec\":" + _staleSec + ",");
        sb.Append("\"restarts\":" + restarts + ",");
        sb.Append("\"restarts_last_hour\":" + recent + ",");
        sb.Append("\"last_reason\":\"" + Esc(lastReason) + "\",");
        sb.Append("\"last_restart_at\":\"" + Esc(lastRestart) + "\",");
        sb.Append("\"restart_stamps\":[" + stampsJson + "],");
        sb.Append("\"checked_at\":\"" + DateTime.Now.ToString("s") + "\",");
        sb.Append("\"body_pid\":" + bodyPid + ",");
        sb.Append("\"body_alive\":" + (bodyAlive ? "true" : "false") + ",");
        sb.Append("\"beacon_age_sec\":" + age + ",");
        sb.Append("\"body_phase\":\"" + Esc(phase) + "\",");
        sb.Append("\"body_job\":\"" + Esc(jobDesc) + "\",");
        sb.Append("\"launcher_pid\":" + launcherPid + ",");
        sb.Append("\"healthy\":" + (healthy ? "true" : "false") + ",");
        sb.Append("\"reason\":\"" + Esc(reason) + "\",");
        sb.Append("\"last_ok\":\"" + Esc(lastOk) + "\"");
        sb.Append("}");
        WriteAll(_stats, sb.ToString());
    }

    // ---------------------------------------------------------------- helpers
    static string ReadAll(string p)
    {
        try { return File.Exists(p) ? File.ReadAllText(p) : ""; } catch { return ""; }
    }
    static void WriteAll(string p, string text)
    {
        try
        {
            string tmp = p + ".new";
            File.WriteAllText(tmp, text, new UTF8Encoding(false));
            if (File.Exists(p)) File.Delete(p);
            File.Move(tmp, p);
        }
        catch { }
    }
    static long Unix() { return (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds; }
    static string Esc(string s) { return (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\""); }

    static readonly Regex _num = new Regex("\"(?:pid|ts|restarts)\"\\s*:\\s*(\\d+)");
    static long Num(string json, string key)
    {
        Match m = Regex.Match(json ?? "", "\"" + Regex.Escape(key) + "\"\\s*:\\s*(\\d+)");
        return m.Success ? long.Parse(m.Groups[1].Value) : 0;
    }
    static string Str(string json, string key)
    {
        Match m = Regex.Match(json ?? "", "\"" + Regex.Escape(key) + "\"\\s*:\\s*\"([^\"]*)\"");
        return m.Success ? m.Groups[1].Value : "";
    }
    static int IntOr(string s, int dflt)
    {
        int v;
        return int.TryParse(s, out v) ? v : dflt;
    }
    static string Get(Dictionary<string, string> d, string k)
    {
        string v;
        return d.TryGetValue(k, out v) ? v : "";
    }
    static Dictionary<string, string> ReadStats()
    {
        Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string json = ReadAll(_stats);
        if (json.Length == 0) return d;
        foreach (string key in new string[] { "restarts", "last_reason", "last_restart_at", "last_ok", "pid", "checked_at" })
        {
            string s = Str(json, key);
            if (s.Length > 0) d[key] = s;
        }
        Match stamps = Regex.Match(json, "\"restart_stamps\"\\s*:\\s*\\[([^\\]]*)\\]");
        if (stamps.Success) d["restart_stamps"] = stamps.Groups[1].Value;
        return d;
    }
    static List<long> Stamps(string csv)
    {
        List<long> list = new List<long>();
        if (string.IsNullOrEmpty(csv)) return list;
        foreach (string part in csv.Split(','))
        {
            long v;
            if (long.TryParse(part.Trim(), out v)) list.Add(v);
        }
        return list;
    }

    static bool Alive(int pid)
    {
        try { using (Process p = Process.GetProcessById(pid)) { return !p.HasExited; } }
        catch { return false; }
    }

    static void KillTree(long pid)
    {
        if (pid <= 0) return;
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo("taskkill.exe", "/PID " + pid + " /T /F");
            psi.CreateNoWindow = true;
            psi.UseShellExecute = false;
            using (Process p = Process.Start(psi)) { p.WaitForExit(10000); }
        }
        catch { }
        Thread.Sleep(1500);
        if (Alive((int)pid)) { try { Process.GetProcessById((int)pid).Kill(); } catch { } }
    }

    static void ReleaseLock(long deadPid)
    {
        try
        {
            if (!File.Exists(_bodyLock)) return;
            string txt = File.ReadAllText(_bodyLock).Trim();
            long lockPid = 0;
            string first = txt.Split(' ')[0];
            long.TryParse(first, out lockPid);
            if (lockPid == deadPid || !Alive((int)lockPid)) File.Delete(_bodyLock);
        }
        catch { }
    }

    static int LauncherPid()
    {
        try
        {
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                "SELECT ProcessId,CommandLine FROM Win32_Process WHERE Name='cmd.exe'"))
            {
                foreach (ManagementObject mo in searcher.Get())
                {
                    object cl = mo["CommandLine"];
                    if (cl == null) continue;
                    if (cl.ToString().IndexOf(_launcherName, StringComparison.OrdinalIgnoreCase) >= 0)
                        return Convert.ToInt32(mo["ProcessId"]);
                }
            }
        }
        catch { }
        return 0;
    }

    static void StartLauncher()
    {
        try
        {
            if (!File.Exists(_launcher)) { Log("launcher missing: " + _launcher + " - run install.cmd on this machine"); return; }
            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c \"" + _launcher + "\"");
            psi.WorkingDirectory = _dir;
            psi.CreateNoWindow = true;
            psi.UseShellExecute = false;
            psi.RedirectStandardInput = true;
            Process p = Process.Start(psi);
            if (p != null) { try { p.StandardInput.Close(); } catch { } }
            Log("launcher started (" + _launcherName + ")");
            Thread.Sleep(3000);
            if (LauncherPid() == 0) Log("WARNING: launcher did not appear");
        }
        catch (Exception ex) { Log("failed to start launcher: " + ex.Message); }
    }

    static void Log(string msg)
    {
        string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + msg;
        if (!_quiet) Console.WriteLine(line);
        try
        {
            FileInfo fi = new FileInfo(_log);
            if (fi.Exists && fi.Length > 1000000)
            {
                try { if (File.Exists(_log + ".1")) File.Delete(_log + ".1"); File.Move(_log, _log + ".1"); } catch { }
            }
            File.AppendAllText(_log, line + "\r\n", Encoding.ASCII);
        }
        catch { }
    }
}
