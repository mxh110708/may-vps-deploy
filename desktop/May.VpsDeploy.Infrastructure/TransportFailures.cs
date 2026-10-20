using System.Net.Sockets;
using Renci.SshNet.Common;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public static class TransportFailures
{
    public static OperationException Describe(Exception error, string phase = "SSH") => error switch
    {
        OperationException safe => safe,
        SshOperationTimeoutException => new(phase + " 连接或请求超时。", code: "SshTimeout", nextAction: "确认当前 SSH 端口可登录，并核对网络；人工身份确认不计入连接超时。"),
        SshAuthenticationException => new("SSH 登录认证失败。", code: "SshAuthenticationFailed", nextAction: "核对登录账号、密码或所选私钥，以及服务器允许的认证方式。"),
        SocketException socket => new(socket.SocketErrorCode switch
        {
            SocketError.ConnectionRefused => "服务器拒绝 SSH 连接。",
            SocketError.HostNotFound or SocketError.NoData => "无法解析服务器地址。",
            SocketError.NetworkUnreachable or SocketError.HostUnreachable => "无法到达服务器网络。",
            SocketError.AccessDenied => "当前环境阻止了网络连接。",
            SocketError.TimedOut => "连接服务器超时。",
            _ => "SSH 网络连接中断。"
        }, code: "SshNetwork" + socket.SocketErrorCode, nextAction: "核对服务器地址、当前 SSH 端口、网络和访问限制。"),
        SftpPermissionDeniedException => new("SFTP 无权读写所需文件。", code: "SftpAccessDenied", nextAction: "核对 SSH 登录账号和远端目录权限。"),
        SftpPathNotFoundException => new("SFTP 所需的远端路径不存在。", code: "SftpPathMissing", nextAction: "查看任务阶段，核对远端文件和目录。"),
        SshConnectionException => new(phase + " 会话在连接或传输期间中断。", code: "SshDisconnected", nextAction: "核对 SSH 服务和网络；存在未确认写入时先核对事务。"),
        _ => SafeFailures.Describe(error)
    };
}
