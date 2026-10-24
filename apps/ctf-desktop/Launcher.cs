using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Web.Script.Serialization;
using System.Windows.Forms;

static class Launcher {
    static string Quote(string text) {
        // Correctly quote Windows arguments, including trailing backslashes.
        var result = new System.Text.StringBuilder("\"");
        int slash = 0;
        foreach (char value in text) {
            if (value == '\\') { slash++; continue; }
            if (value == '"') result.Append('\\', slash * 2 + 1);
            else result.Append('\\', slash);
            result.Append(value); slash = 0;
        }
        result.Append('\\', slash * 2); result.Append('"');
        return result.ToString();
    }
    [STAThread]
    static void Main() {
        string folder = AppDomain.CurrentDomain.BaseDirectory;
        string log = Path.Combine(folder, "data", "launcher.log");
        try {
            string location = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ctf-system", "location.json");
            if (!File.Exists(location)) throw new Exception("未找到 CTF 系统安装登记。请先完成原系统安装。\n也可使用随附启动脚本指定系统路径。");
            var settings = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(File.ReadAllText(location));
            string python = Environment.GetEnvironmentVariable("CTF_PYTHON");
            if (String.IsNullOrEmpty(python)) python = Convert.ToString(settings["python"]);
            string root = Convert.ToString(settings["root"]);
            if (!File.Exists(python)) throw new Exception("系统登记的 Python 已不存在：" + python);
            if (!File.Exists(Path.Combine(root, "tools", "ctf_entry.py"))) throw new Exception("找不到 CTF 系统核心：" + root);
            Directory.CreateDirectory(Path.GetDirectoryName(log));
            var info = new ProcessStartInfo(python);
            info.Arguments = "-X utf8 -B " + Quote(Path.Combine(folder, "app_server.py")) + " --root " + Quote(root) + " --home " + Quote(Path.Combine(folder, "data")) + " --open";
            info.WorkingDirectory = folder;
            info.CreateNoWindow = true; info.UseShellExecute = false;
            info.RedirectStandardError = true; info.RedirectStandardOutput = true;
            info.EnvironmentVariables["PYTHONDONTWRITEBYTECODE"] = "1";
            using (var process = new Process()) {
                process.StartInfo = info;
                process.ErrorDataReceived += (sender, args) => { if (args.Data != null) { lock (log) File.AppendAllText(log, args.Data + Environment.NewLine); } };
                process.Start(); process.BeginErrorReadLine();
                process.BeginOutputReadLine();
                process.WaitForExit();
                if (process.ExitCode != 0) MessageBox.Show("CTF 系统应用未能启动，请查看：\n" + log, "CTF 系统", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        } catch (Exception error) {
            MessageBox.Show(error.Message, "CTF 系统", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
