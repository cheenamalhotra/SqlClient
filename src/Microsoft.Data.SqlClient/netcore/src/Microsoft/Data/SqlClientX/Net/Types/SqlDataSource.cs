// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Text;
using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClientX.Net.Helpers;

namespace Microsoft.Data.SqlClientX.Net.Types
{
    internal class SqlDataSource
    {
        private const char CommaSeparator = ',';
        private const char SemiColon = ':';
        private const char BackSlashCharacter = '\\';

        private const string DefaultHostName = "localhost";
        private const string DefaultSqlServerInstanceName = "mssqlserver";
        private const string PipeBeginning = @"\\";
        private const string Slash = @"/";
        private const string PipeToken = "pipe";
        private const string LocalDbHost = "(localdb)";
        private const string LocalDbHost_NP = @"np:\\.\pipe\LOCALDB#";
        private const string NamedPipeInstanceNameHeader = "mssql$";
        private const string DefaultPipeName = "sql\\query";
        private const string InstancePrefix = "MSSQL$";
        private const string PathSeparator = "\\";

        internal enum Protocol { TCP, NP, None, Admin };

        internal Protocol _connectionProtocol = Protocol.None;

        /// <summary>
        /// Provides the HostName of the server to connect to for TCP protocol.
        /// This information is also used for finding the SPN of SqlServer
        /// </summary>
        internal string ServerName { get; private set; }

        /// <summary>
        /// Provides the port on which the TCP connection should be made if one was specified in Data Source
        /// </summary>
        internal int Port { get; private set; } = -1;

        /// <summary>
        /// The port resolved by SSRP when InstanceName is specified
        /// </summary>
        internal int ResolvedPort { get; set; } = -1;

        /// <summary>
        /// Provides the inferred Instance Name from Server Data Source
        /// </summary>
        internal string InstanceName { get; private set; }

        /// <summary>
        /// Provides the pipe name in case of Named Pipes
        /// </summary>
        internal string PipeName { get; private set; }

        /// <summary>
        /// Provides the HostName to connect to in case of Named pipes Data Source
        /// </summary>
        internal string PipeHostName { get; private set; }

        private string _workingDataSource;
        private string _dataSourceAfterTrimmingProtocol;

        internal bool IsBadDataSource { get; private set; } = false;

        internal bool IsSsrpRequired { get; private set; } = false;

        private SqlDataSource(string dataSource)
        {
            // Remove all whitespaces from the datasource and all operations will happen on lower case.
            _workingDataSource = dataSource.Trim().ToLowerInvariant();

            int firstIndexOfColon = _workingDataSource.IndexOf(SemiColon);

            PopulateProtocol();

            _dataSourceAfterTrimmingProtocol = (firstIndexOfColon > -1) && _connectionProtocol != Protocol.None
                ? _workingDataSource.Substring(firstIndexOfColon + 1).Trim() : _workingDataSource;

            if (_dataSourceAfterTrimmingProtocol.Contains(Slash)) // Pipe paths only allow back slashes
            {
                if (_connectionProtocol == Protocol.None)
                    ReportSNIError(Providers.INVALID_PROV);
                else if (_connectionProtocol == Protocol.NP)
                    ReportSNIError(Providers.NP_PROV);
                else if (_connectionProtocol == Protocol.TCP)
                    ReportSNIError(Providers.TCP_PROV);
            }
        }

        private void PopulateProtocol()
        {
            string[] splitByColon = _workingDataSource.Split(SemiColon);

            if (splitByColon.Length <= 1)
            {
                _connectionProtocol = Protocol.None;
            }
            else
            {
                // We trim before switching because " tcp : server , 1433 " is a valid data source
                switch (splitByColon[0].Trim())
                {
                    case TdsEnums.TCP:
                        _connectionProtocol = Protocol.TCP;
                        break;
                    case TdsEnums.NP:
                        _connectionProtocol = Protocol.NP;
                        break;
                    case TdsEnums.ADMIN:
                        _connectionProtocol = Protocol.Admin;
                        break;
                    default:
                        // None of the supported protocols were found. This may be a IPv6 address
                        _connectionProtocol = Protocol.None;
                        break;
                }
            }
        }

        // LocalDbInstance name always starts with (localdb)
        // possible scenarios:
        // (localdb)\<instance name>
        // or (localdb)\. which goes to default localdb
        // or (localdb)\.\<sharedInstance name>
        internal static string GetLocalDBInstance(string dataSource, out bool error)
        {
            string instanceName = null;
            ReadOnlySpan<char> input = dataSource.AsSpan().TrimStart();
            error = false;
            int index = input.IndexOf(LocalDbHost.AsSpan().Trim(), StringComparison.InvariantCultureIgnoreCase);
            if (input.StartsWith(LocalDbHost_NP.AsSpan().Trim(), StringComparison.InvariantCultureIgnoreCase))
            {
                instanceName = input.Trim().ToString();
            }
            else if (index > 0)
            {
                GlobalErrorHandler.Instance.LastError = new SqlNetworkError(Providers.INVALID_PROV, 0, Constants.ErrorLocatingServerInstance, Strings.SNI_ERROR_26);
                SqlClientEventSource.Log.TrySNITraceEvent(nameof(SqlDataSource), EventType.ERR, "Incompatible use of prefix with LocalDb: '{0}'", dataSource);
                error = true;
            }
            else if (index == 0)
            {
                // When netcoreapp support for netcoreapp2.1 is dropped these slice calls could be converted to System.Range\System.Index
                // Such ad input = input[1..];
                input = input.Slice(LocalDbHost.Length);
                if (!input.IsEmpty && input[0] == BackSlashCharacter)
                {
                    input = input.Slice(1);
                }
                if (!input.IsEmpty)
                {
                    instanceName = input.Trim().ToString();
                }
                else
                {
                    GlobalErrorHandler.Instance.LastError = new SqlNetworkError(Providers.INVALID_PROV, 0, Constants.LocalDBNoInstanceName, Strings.SNI_ERROR_51);
                    error = true;
                }
            }

            return instanceName;
        }

        internal static SqlDataSource ParseServerName(string dataSource)
        {
            SqlDataSource details = new SqlDataSource(dataSource);

            if (details.IsBadDataSource)
            {
                return null;
            }

            if (details.InferNamedPipesInformation())
            {
                return details;
            }

            if (details.IsBadDataSource)
            {
                return null;
            }

            if (details.InferConnectionDetails())
            {
                return details;
            }

            return null;
        }

        private void InferLocalServerName()
        {
            // If Server name is empty or localhost, then use "localhost"
            if (string.IsNullOrEmpty(ServerName) || IsLocalHost(ServerName) ||
                (Environment.MachineName.Equals(ServerName, StringComparison.CurrentCultureIgnoreCase) &&
                 _connectionProtocol == Protocol.Admin))
            {
                // For DAC use "localhost" instead of the server name.
                ServerName = DefaultHostName;
            }
        }

        private bool InferConnectionDetails()
        {
            string[] tokensByCommaAndSlash = _dataSourceAfterTrimmingProtocol.Split(BackSlashCharacter, CommaSeparator);
            ServerName = tokensByCommaAndSlash[0].Trim();

            int commaIndex = _dataSourceAfterTrimmingProtocol.IndexOf(CommaSeparator);

            int backSlashIndex = _dataSourceAfterTrimmingProtocol.IndexOf(BackSlashCharacter);

            // Check the parameters. The parameters are Comma separated in the Data Source. The parameter we really care about is the port
            // If Comma exists, the try to get the port number
            if (commaIndex > -1)
            {
                string parameter = backSlashIndex > -1
                        ? ((commaIndex > backSlashIndex) ? tokensByCommaAndSlash[2].Trim() : tokensByCommaAndSlash[1].Trim())
                        : tokensByCommaAndSlash[1].Trim();

                // Bad Data Source like "server, "
                if (string.IsNullOrEmpty(parameter))
                {
                    ReportSNIError(Providers.INVALID_PROV);
                    return false;
                }

                // For Tcp and Only Tcp are parameters allowed.
                if (_connectionProtocol == Protocol.None)
                {
                    _connectionProtocol = Protocol.TCP;
                }
                else if (_connectionProtocol != Protocol.TCP)
                {
                    // Parameter has been specified for non-TCP protocol. This is not allowed.
                    ReportSNIError(Providers.INVALID_PROV);
                    return false;
                }

                int port;
                if (!int.TryParse(parameter, out port))
                {
                    ReportSNIError(Providers.TCP_PROV);
                    return false;
                }

                // If the user explicitly specified a invalid port in the connection string.
                if (port < 1)
                {
                    ReportSNIError(Providers.TCP_PROV);
                    return false;
                }

                Port = port;
            }
            // Instance Name Handling. Only if we found a '\' and we did not find a port in the Data Source
            else if (backSlashIndex > -1)
            {
                // This means that there will not be any part separated by comma.
                InstanceName = tokensByCommaAndSlash[1].Trim();

                if (string.IsNullOrWhiteSpace(InstanceName))
                {
                    ReportSNIError(Providers.INVALID_PROV);
                    return false;
                }

                if (DefaultSqlServerInstanceName.Equals(InstanceName))
                {
                    ReportSNIError(Providers.INVALID_PROV);
                    return false;
                }

                IsSsrpRequired = true;
            }

            InferLocalServerName();

            return true;
        }

        private void ReportSNIError(Providers provider)
        {
            GlobalErrorHandler.Instance.LastError = new SqlNetworkError(provider, 0, Constants.InvalidConnStringError, Strings.SNI_ERROR_25);
            IsBadDataSource = true;
        }

        private bool InferNamedPipesInformation()
        {
            // If we have a datasource beginning with a pipe or we have already determined that the protocol is Named Pipe
            if (_dataSourceAfterTrimmingProtocol.StartsWith(PipeBeginning, StringComparison.Ordinal) || _connectionProtocol == Protocol.NP)
            {
                // If the data source starts with "np:servername"
                if (!_dataSourceAfterTrimmingProtocol.Contains(PipeBeginning))
                {
                    // Assuming that user did not change default NamedPipe name, if the datasource is in the format servername\instance, 
                    // separate servername and instance and prepend instance with MSSQL$ and append default pipe path 
                    // https://learn.microsoft.com/en-us/sql/tools/configuration-manager/named-pipes-properties?view=sql-server-ver16
                    if (_dataSourceAfterTrimmingProtocol.Contains(PathSeparator) && _connectionProtocol == Protocol.NP)
                    {
                        string[] tokensByBackSlash = _dataSourceAfterTrimmingProtocol.Split(BackSlashCharacter);
                        if (tokensByBackSlash.Length == 2)
                        {
                            // NamedPipeClientStream object will create the network path using PipeHostName and PipeName
                            // and can be seen in its _normalizedPipePath variable in the format \\servername\pipe\MSSQL$<instancename>\sql\query
                            PipeHostName = ServerName = tokensByBackSlash[0];
                            PipeName = $"{InstancePrefix}{tokensByBackSlash[1]}{PathSeparator}{DefaultPipeName}";
                        }
                        else
                        {
                            ReportSNIError(Providers.NP_PROV);
                            return false;
                        }
                    }
                    else
                    {
                        PipeHostName = ServerName = _dataSourceAfterTrimmingProtocol;
                        PipeName = NpMessenger.DefaultPipePath;
                    }

                    InferLocalServerName();
                    return true;
                }

                try
                {
                    string[] tokensByBackSlash = _dataSourceAfterTrimmingProtocol.Split(BackSlashCharacter);

                    // The datasource is of the format \\host\pipe\sql\query [0]\[1]\[2]\[3]\[4]\[5]
                    // It would at least have 6 parts.
                    // Another valid Sql named pipe for an named instance is \\.\pipe\MSSQL$MYINSTANCE\sql\query
                    if (tokensByBackSlash.Length < 6)
                    {
                        ReportSNIError(Providers.NP_PROV);
                        return false;
                    }

                    string host = tokensByBackSlash[2];

                    if (string.IsNullOrEmpty(host))
                    {
                        ReportSNIError(Providers.NP_PROV);
                        return false;
                    }

                    //Check if the "pipe" keyword is the first part of path
                    if (!PipeToken.Equals(tokensByBackSlash[3]))
                    {
                        ReportSNIError(Providers.NP_PROV);
                        return false;
                    }

                    if (tokensByBackSlash[4].StartsWith(NamedPipeInstanceNameHeader, StringComparison.Ordinal))
                    {
                        InstanceName = tokensByBackSlash[4].Substring(NamedPipeInstanceNameHeader.Length);
                    }

                    StringBuilder pipeNameBuilder = new StringBuilder();

                    for (int i = 4; i < tokensByBackSlash.Length - 1; i++)
                    {
                        pipeNameBuilder.Append(tokensByBackSlash[i]);
                        pipeNameBuilder.Append(Path.DirectorySeparatorChar);
                    }
                    // Append the last part without a "/"
                    pipeNameBuilder.Append(tokensByBackSlash[tokensByBackSlash.Length - 1]);
                    PipeName = pipeNameBuilder.ToString();

                    if (string.IsNullOrWhiteSpace(InstanceName) && !DefaultPipeName.Equals(PipeName))
                    {
                        InstanceName = PipeToken + PipeName;
                    }

                    ServerName = IsLocalHost(host) ? Environment.MachineName : host;
                    // Pipe hostname is the hostname after leading \\ which should be passed down as is to open Named Pipe.
                    // For Named Pipes the ServerName makes sense for SPN creation only.
                    PipeHostName = host;
                }
                catch (UriFormatException)
                {
                    ReportSNIError(Providers.NP_PROV);
                    return false;
                }

                // DataSource is something like "\\pipename"
                if (_connectionProtocol == Protocol.None)
                {
                    _connectionProtocol = Protocol.NP;
                }
                else if (_connectionProtocol != Protocol.NP)
                {
                    // In case the path began with a "\\" and protocol was not Named Pipes
                    ReportSNIError(Providers.NP_PROV);
                    return false;
                }
                return true;
            }
            return false;
        }

        private static bool IsLocalHost(string serverName)
            => ".".Equals(serverName) || "(local)".Equals(serverName) || "localhost".Equals(serverName);
    }
}
