using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using System.Security;
using System.Threading;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace May.VpsDeploy.Gui
{
    public sealed class Notice
    {
        public string Kind { get; set; }
        public string Text { get; set; }
        public int Percent { get; set; } = -1;
    }

    public sealed class InputRequest
    {
        readonly ManualResetEventSlim ready = new ManualResetEventSlim(false);
        int completed;
        public string Kind { get; set; }
        public string Title { get; set; }
        public string DefaultValue { get; set; }
        public string[] Options { get; set; } = Array.Empty<string>();
        public int DefaultIndex { get; set; }
        public bool AllowBack { get; set; }
        public string BackValue { get; set; } = "0";
        public string HelpText { get; set; }
        public bool CanClear { get; set; }
        public string Value { get; private set; }
        public SecureString Secret { get; private set; }
        public bool Canceled { get; private set; }
        public bool IsCompleted => Volatile.Read(ref completed) != 0;

        public bool Respond(string value)
        {
            if (Interlocked.CompareExchange(ref completed, 1, 0) != 0) return false;
            Value = value;
            ready.Set();
            return true;
        }
        public bool RespondSecret(SecureString value)
        {
            if (Interlocked.CompareExchange(ref completed, 1, 0) != 0) return false;
            Secret = value;
            ready.Set();
            return true;
        }
        public void Cancel()
        {
            if (Interlocked.CompareExchange(ref completed, 1, 0) != 0) return;
            Canceled = true;
            ready.Set();
        }
        internal void Wait() => ready.Wait();
    }

    // Each task gets its own host, runspace and broker. No global console or proxy state.
    public sealed class Session : IDisposable
    {
        public ConcurrentQueue<Notice> Notices { get; } = new ConcurrentQueue<Notice>();
        public ConcurrentQueue<InputRequest> Requests { get; } = new ConcurrentQueue<InputRequest>();
        public bool CancelRequested { get; private set; }
        public bool Running { get; private set; }
        public bool Failed { get; private set; }
        public bool Completed { get; private set; }
        public bool HasWarnings { get; private set; }
        public bool NavigatedBack { get; private set; }
        public string ArchiveRoot { get; private set; } = "";
        public string ErrorMessage { get; private set; }
        public PSDataCollection<PSObject> Result { get; private set; }
        readonly Dictionary<string,string> initialAnswers = new Dictionary<string,string>(StringComparer.Ordinal);
        InputRequest pending;
        readonly object gate = new object();
        Runspace runspace;
        PowerShell pipeline;
        IAsyncResult invocation;

        public void Publish(string kind, string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return;
            if (kind == "Warning") HasWarnings = true;
            while (Notices.Count > 1500) Notices.TryDequeue(out _);
            Notices.Enqueue(new Notice { Kind = kind, Text = text });
        }
        public void Progress(string activity, int percent)
        {
            Notices.Enqueue(new Notice { Kind = "Progress", Text = activity, Percent = percent });
        }
        InputRequest Request(InputRequest request)
        {
            lock (gate)
            {
                if (CancelRequested) { request.Cancel(); return request; }
                pending = request;
                Requests.Enqueue(request);
            }
            request.Wait();
            lock (gate) { if (ReferenceEquals(pending, request)) pending = null; }
            return request;
        }
        public string ReadText(string title, string value, bool back, string backValue, string help, bool clear)
        {
            if (TakeInitialAnswer(title, out var answer)) return answer;
            var r = Request(new InputRequest { Kind = "text", Title = title, DefaultValue = value,
                AllowBack = back, BackValue = backValue, HelpText = help, CanClear = clear });
            return r.Canceled ? null : r.Value;
        }
        public string ReadChoice(string title, string[] options, int selected, bool back, string help, string kind)
        {
            if (TakeInitialAnswer(title, out var answer)) return answer;
            var r = Request(new InputRequest { Kind = kind, Title = title, Options = options,
                DefaultIndex = selected, AllowBack = back, HelpText = help });
            return r.Canceled ? null : r.Value;
        }
        public SecureString ReadSecret(string title, bool back)
        {
            var r = Request(new InputRequest { Kind = "secret", Title = title, AllowBack = back });
            return r.Canceled ? null : r.Secret;
        }
        public string ReadMultiple(string title, string[] options, bool allowEmpty)
        {
            var r = Request(new InputRequest { Kind="multiple", Title=title, Options=options,
                AllowBack=true, CanClear=allowEmpty, DefaultIndex=-1 });
            return r.Canceled ? null : r.Value;
        }
        public void SetInitialAnswers(Dictionary<string,string> values)
        {
            lock(gate) { foreach(var pair in values) initialAnswers[pair.Key]=pair.Value; }
        }
        bool TakeInitialAnswer(string title, out string value)
        {
            lock(gate) {
                value=null;
                if(CancelRequested || !initialAnswers.TryGetValue(title,out value)) return false;
                initialAnswers.Remove(title); return true;
            }
        }
        public void CancelPendingInput() { lock(gate) pending?.Cancel(); }
        public void Cancel()
        {
            lock (gate) { CancelRequested = true; pending?.Cancel(); }
            Publish("Warning", "已请求取消；等待当前操作到达可返回的位置，恢复保护继续保留。");
        }
        public void MarkNavigationEnd() { NavigatedBack = true; }
        public void StartWorkflow(string root, string mode, string instanceRoot, string planPath, string proxy)
        {
            ArchiveRoot = instanceRoot;
            const string script = @"
param($Root,$Mode,$InstanceRoot,$PlanPath,$Session,$Proxy)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $Root 'src/VpsDeploy.Core.psm1') -Force
Set-VpsInteractionSession -Session $Session
if($Mode -in @('CheckUpdate','ApplyUpdate')) {
    Import-Module (Join-Path $Root 'src/VpsDeploy.Update.psm1') -Force
    try {
        if($Mode -eq 'CheckUpdate') { Get-VpsApplicationUpdate -ProjectRoot $Root -Proxy $Proxy }
        else { Start-VpsApplicationUpdate -ProjectRoot $Root -Proxy $Proxy -ParentProcessId $PID -InteractionSession $Session }
    } catch {
        if($_.Exception.Message -eq '__MXH_VPS_WIZARD_CANCEL__') { $Session.MarkNavigationEnd() }
        else { throw }
    }
} else {
    Start-VpsDeploy -ProjectRoot $Root -Mode $Mode -InstanceRoot $InstanceRoot -PlanPath $PlanPath
}";
            StartScript(script, new Dictionary<string, object> {
                {"Root",root},{"Mode",mode},{"InstanceRoot",instanceRoot},{"PlanPath",planPath},
                {"Session",this},{"Proxy",proxy ?? ""}
            });
        }
        public void StartScript(string script, Dictionary<string, object> parameters)
        {
            if (Running || pipeline != null) throw new InvalidOperationException("任务已启动。");
            runspace = RunspaceFactory.CreateRunspace(new GuiHost(this));
            runspace.ApartmentState = ApartmentState.STA;
            runspace.ThreadOptions = PSThreadOptions.ReuseThread;
            runspace.Open();
            pipeline = PowerShell.Create();
            pipeline.Runspace = runspace;
            pipeline.AddScript(script).AddParameters(parameters);
            Running = true;
            invocation = pipeline.BeginInvoke();
        }
        public bool Poll()
        {
            if (!Running || invocation == null || !invocation.IsCompleted) return Completed;
            try { Result = pipeline.EndInvoke(invocation); }
            catch (Exception ex) { Failed = true; ErrorMessage = ex.Message; }
            if (pipeline.HadErrors)
            {
                Failed = true;
                if (string.IsNullOrWhiteSpace(ErrorMessage) && pipeline.Streams.Error.Count > 0)
                    ErrorMessage = pipeline.Streams.Error[0].Exception.Message;
            }
            Running = false; Completed = true;
            if (Failed) Publish("Error", ErrorMessage ?? "操作失败。请查看执行记录。");
            return true;
        }
        public void Dispose()
        {
            if (Running) throw new InvalidOperationException("执行中的任务不能强制停止。");
            pipeline?.Dispose();
            runspace?.Dispose();
            Result?.Dispose();
        }
    }

    // OpenSSH askpass exchanges credentials in memory, only with this Windows user.
    public sealed class SshSecretBroker : IDisposable
    {
        readonly Session session;
        readonly object gate = new object();
        readonly Task worker;
        NamedPipeServerStream pipe;
        bool stopping;
        public string PipeName { get; } = "mxh-vps-askpass-" + Guid.NewGuid().ToString("N");
        public SshSecretBroker(Session owner) { session=owner; worker=Task.Run(Serve); }
        void Serve()
        {
            try {
                while(true) {
                    NamedPipeServerStream current;
                    lock(gate) {
                        if(stopping) return;
                        pipe=new NamedPipeServerStream(PipeName,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.CurrentUserOnly);
                        current=pipe;
                    }
                    using(current) {
                        current.WaitForConnection();
                        using(var reader=new BinaryReader(current,System.Text.Encoding.UTF8,true))
                        using(var writer=new BinaryWriter(current,System.Text.Encoding.UTF8,true)) {
                            string prompt=reader.ReadString();
                            if(prompt.Length>2048) throw new IOException("SSH 提示过长。");
                            using(var secret=session.ReadSecret("SSH 认证凭据 · " + prompt,false)) {
                                writer.Write(secret!=null);
                                if(secret!=null) {
                                    IntPtr pointer=Marshal.SecureStringToBSTR(secret);
                                    try { writer.Write(Marshal.PtrToStringBSTR(pointer)); }
                                    finally { Marshal.ZeroFreeBSTR(pointer); }
                                }
                                writer.Flush();
                            }
                        }
                    }
                }
            } catch(Exception) { lock(gate) { if(!stopping) session.Publish("Warning","SSH 图形认证已结束。请检查连接结果。"); } }
        }
        public void Dispose()
        {
            lock(gate) { stopping=true; pipe?.Dispose(); }
            session.CancelPendingInput();
            worker.Wait(2000);
        }
    }

    sealed class GuiHost : PSHost
    {
        readonly Guid id = Guid.NewGuid();
        readonly GuiUserInterface ui;
        public GuiHost(Session session) { ui = new GuiUserInterface(session); }
        public override Guid InstanceId => id;
        public override string Name => "May VPS Deploy GUI";
        public override Version Version => new Version(1, 0);
        public override PSHostUserInterface UI => ui;
        public override CultureInfo CurrentCulture => CultureInfo.CurrentCulture;
        public override CultureInfo CurrentUICulture => CultureInfo.CurrentUICulture;
        public override void SetShouldExit(int exitCode) { if (exitCode != 0) ui.WriteErrorLine("任务退出码：" + exitCode); }
        public override void EnterNestedPrompt() => throw new NotSupportedException("不支持嵌套终端。");
        public override void ExitNestedPrompt() { }
        public override void NotifyBeginApplication() { }
        public override void NotifyEndApplication() { }
    }

    sealed class GuiUserInterface : PSHostUserInterface
    {
        readonly Session session;
        readonly GuiRawUserInterface raw = new GuiRawUserInterface();
        public GuiUserInterface(Session session) { this.session = session; }
        public override PSHostRawUserInterface RawUI => raw;
        public override string ReadLine() => session.ReadText("请输入", "", false, "0", "", false);
        public override SecureString ReadLineAsSecureString() => session.ReadSecret("请输入凭据", false);
        public override void Write(string value) => session.Publish("Output", value);
        public override void Write(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value) => Write(value);
        public override void WriteLine(string value) => Write(value);
        public override void WriteErrorLine(string value) => session.Publish("Error", value);
        public override void WriteDebugLine(string value) => session.Publish("Muted", value);
        public override void WriteVerboseLine(string value) => session.Publish("Muted", value);
        public override void WriteWarningLine(string value) => session.Publish("Warning", value);
        public override void WriteProgress(long sourceId, ProgressRecord record) => session.Progress(record.Activity, record.PercentComplete);
        public override Dictionary<string, PSObject> Prompt(string caption, string message, Collection<FieldDescription> descriptions)
        {
            var values = new Dictionary<string, PSObject>();
            foreach (var field in descriptions)
            {
                object value = field.ParameterTypeName == "SecureString"
                    ? (object)session.ReadSecret(message + field.Label, false)
                    : session.ReadText(message + field.Label, "", false, "0", field.HelpMessage, false);
                if (value == null) throw new OperationCanceledException("__MXH_VPS_WIZARD_CANCEL__");
                values.Add(field.Name, PSObject.AsPSObject(value));
            }
            return values;
        }
        public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName)
            => PromptForCredential(caption, message, userName, targetName, PSCredentialTypes.Default, PSCredentialUIOptions.Default);
        public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName,
            PSCredentialTypes types, PSCredentialUIOptions options)
        {
            var name = session.ReadText("用户名", userName, false, "0", "", false);
            var password = session.ReadSecret("密码", false);
            if (name == null || password == null) throw new OperationCanceledException("__MXH_VPS_WIZARD_CANCEL__");
            return new PSCredential(name, password);
        }
        public override int PromptForChoice(string caption, string message, Collection<ChoiceDescription> choices, int defaultChoice)
        {
            var labels = new string[choices.Count];
            for (int i = 0; i < choices.Count; i++) labels[i] = choices[i].Label.Replace("&", "");
            var answer = session.ReadChoice(caption + message, labels, defaultChoice, false, "", "menu");
            if (answer == null) throw new OperationCanceledException("__MXH_VPS_WIZARD_CANCEL__");
            return int.Parse(answer, CultureInfo.InvariantCulture) - 1;
        }
    }

    sealed class GuiRawUserInterface : PSHostRawUserInterface
    {
        public override ConsoleColor BackgroundColor { get; set; } = ConsoleColor.Black;
        public override ConsoleColor ForegroundColor { get; set; } = ConsoleColor.Gray;
        public override Size BufferSize { get; set; } = new Size(160, 100);
        public override Coordinates CursorPosition { get; set; }
        public override int CursorSize { get; set; } = 1;
        public override bool KeyAvailable => false;
        public override Size MaxPhysicalWindowSize => new Size(160, 100);
        public override Size MaxWindowSize => new Size(160, 100);
        public override Coordinates WindowPosition { get; set; }
        public override Size WindowSize { get; set; } = new Size(160, 100);
        public override string WindowTitle { get; set; } = "May VPS Deploy";
        public override void FlushInputBuffer() { }
        public override BufferCell[,] GetBufferContents(Rectangle rectangle) => throw new NotSupportedException();
        public override KeyInfo ReadKey(ReadKeyOptions options) => throw new NotSupportedException("请使用界面按钮。");
        public override void ScrollBufferContents(Rectangle source, Coordinates destination, Rectangle clip, BufferCell fill) { }
        public override void SetBufferContents(Coordinates origin, BufferCell[,] contents) { }
        public override void SetBufferContents(Rectangle rectangle, BufferCell fill) { }
    }
}
